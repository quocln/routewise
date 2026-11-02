import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { resetWrittenForTests } from "@/lib/use-persisted-state";

const AWS = "/Applications/AWS VPN Client/aws";
const OFFICE = "routewise-wireguard:ab12cd34";

// A fake helper: lists by client id, every call recorded. A plain function,
// not vi.fn(), so a rejection is awaited by the client rather than reported.
let lists: Record<string, string[]>;
let failNext: { code: number; message: string } | undefined;
const calls: { method: string; params: Record<string, unknown> | undefined }[] = [];

function answer(method: string, params: Record<string, unknown> | undefined): Promise<unknown> {
  calls.push({ method, params });
  const vpn = (params?.vpn as string | undefined) ?? "";
  if (method !== "domains.list" && method.startsWith("domains.") && failNext) {
    const { code, message } = failNext;
    failNext = undefined;
    return Promise.reject({ kind: "remote", code, message });
  }
  switch (method) {
    case "settings.get":
      return Promise.resolve({ allowedVpnClients: [{ id: AWS, name: "AWS VPN Client" }, { id: OFFICE, name: "" }] });
    case "profiles.list":
      return Promise.resolve([{ id: "ab12cd34", kind: "wireguard", name: "Office", autoConnect: false, dns: [], state: "connected" }]);
    case "status.get":
      return Promise.resolve({ running: true, vpnConnected: false, routeCount: 0 });
    case "domains.list":
      return Promise.resolve((lists[vpn] ?? []).map((pattern) => ({ pattern })));
    case "domains.add":
      lists[vpn] = [...(lists[vpn] ?? []), params?.pattern as string];
      return Promise.resolve({ success: true });
    case "domains.remove":
      lists[vpn] = (lists[vpn] ?? []).filter((p) => p !== params?.pattern);
      return Promise.resolve({ success: true });
    case "domains.set":
      lists[vpn] = params?.patterns as string[];
      return Promise.resolve({ success: true });
    default:
      return Promise.reject({ kind: "remote", code: -32601, message: `unexpected ${method}` });
  }
}

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (_cmd: string, args: { method: string; params?: Record<string, unknown> }) => answer(args.method, args.params),
  isTauri: () => true,
}));
// jsdom lays nothing out, so the real virtualizer measures a zero-height viewport and renders no
// rows. This one renders every row, which is all these tests need.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({ index, key: index, size: estimateSize(), start: index * estimateSize() })),
  }),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const { DomainsTab } = await import("./domains-tab");

function renderTab(props: { onOpenVpnTab?: () => void } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <DomainsTab {...props} />
    </QueryClientProvider>,
  );
}

const writes = () => calls.filter((c) => c.method !== "domains.list" && c.method.startsWith("domains."));

describe("DomainsTab", () => {
  beforeEach(() => {
    calls.length = 0;
    failNext = undefined;
    lists = { "": ["b.example.com", "a.example.com"], [AWS]: ["aws.example.com", "10.20.0.0/16"], [OFFICE]: [] };
    window.localStorage.clear();
    resetWrittenForTests();
  });

  it("shows every list with its count and the chosen list's sorted entries", async () => {
    renderTab();
    const nav = await screen.findByRole("navigation", { name: "Domain lists" });
    await vi.waitFor(() => expect(within(nav).getAllByLabelText("2 entries")).toHaveLength(2));
    expect(within(nav).getByLabelText("0 entries")).toBeInTheDocument();
    expect(within(nav).getByText("Built-in VPNs")).toBeInTheDocument();
    expect(within(nav).getByText("VPN apps")).toBeInTheDocument();
    // An empty list is still a list, and a built-in client with no name shows its profile's.
    expect(within(nav).getByRole("button", { name: /Office/ })).toBeInTheDocument();
    const entries = await screen.findAllByRole("option");
    expect(entries.map((e) => e.textContent)).toEqual([expect.stringContaining("a.example.com"), expect.stringContaining("b.example.com")]);
  });

  it("switches lists and remembers the choice", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole("button", { name: /AWS VPN Client/ }));
    expect(await screen.findByText("aws.example.com")).toBeInTheDocument();
    expect(screen.getByText("Range")).toBeInTheDocument();
    expect(window.localStorage.getItem("routewise.domains.selectedList")).toBe(JSON.stringify(AWS));
    expect(calls.some((c) => c.method === "domains.list" && c.params?.vpn === AWS)).toBe(true);
  });

  it("restores the stored list on open", async () => {
    window.localStorage.setItem("routewise.domains.selectedList", JSON.stringify(AWS));
    renderTab();
    expect(await screen.findByText("aws.example.com")).toBeInTheDocument();
  });

  it("adds one entry with domains.add and reports it", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("a.example.com");
    await user.type(screen.getByLabelText("Add entries"), "c.example.com{Enter}");
    expect(await screen.findByText("Added.")).toBeInTheDocument();
    expect(writes()).toEqual([{ method: "domains.add", params: { pattern: "c.example.com", vpn: "" } }]);
    expect(await screen.findByText("c.example.com")).toBeInTheDocument();
  });

  it("adds several entries from the helper's current list, skipping duplicates", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("a.example.com");
    await user.type(screen.getByLabelText("Add entries"), "x.example.com, a.example.com 10.30.5.1/16{Enter}");
    expect(await screen.findByText("Added 2; 1 already in the list.")).toBeInTheDocument();
    expect(writes()).toEqual([
      { method: "domains.set", params: { patterns: ["b.example.com", "a.example.com", "x.example.com", "10.30.5.1/16"], vpn: "" } },
    ]);
  });

  it("rejects a malformed entry without calling the helper", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("a.example.com");
    await user.type(screen.getByLabelText("Add entries"), "ex*ample{Enter}");
    expect(await screen.findByText("ex*ample: Invalid pattern format")).toBeInTheDocument();
    expect(writes()).toEqual([]);
    await user.clear(screen.getByLabelText("Add entries"));
    await user.type(screen.getByLabelText("Add entries"), "a.example.com{Enter}");
    expect(await screen.findByText("Already in this list.")).toBeInTheDocument();
    expect(writes()).toEqual([]);
  });

  it("shows the helper's error and keeps what was typed", async () => {
    const user = userEvent.setup();
    failNext = { code: -32000, message: "list is full" };
    renderTab();
    await screen.findByText("a.example.com");
    await user.type(screen.getByLabelText("Add entries"), "c.example.com{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent("list is full");
    expect(screen.getByLabelText("Add entries")).toHaveValue("c.example.com");
  });

  it("removes one entry with domains.remove", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("a.example.com");
    await user.click(screen.getByRole("button", { name: "Remove a.example.com" }));
    await vi.waitFor(() => expect(screen.queryByText("a.example.com")).not.toBeInTheDocument());
    expect(writes()).toEqual([{ method: "domains.remove", params: { pattern: "a.example.com", vpn: "" } }]);
  });

  it("removes a selection in one domains.set", async () => {
    const user = userEvent.setup();
    lists[""] = ["a.example.com", "b.example.com", "c.example.com"];
    renderTab();
    await user.click(await screen.findByText("a.example.com"));
    await user.keyboard("{Shift>}");
    await user.click(screen.getByText("b.example.com"));
    await user.keyboard("{/Shift}");
    await user.click(screen.getByRole("button", { name: "Remove 2 Selected" }));
    await vi.waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0]).toEqual({ method: "domains.set", params: { patterns: ["c.example.com"], vpn: "" } });
  });

  it("removes the right-clicked entry from its context menu", async () => {
    const user = userEvent.setup();
    lists[""] = ["a.example.com", "b.example.com", "c.example.com"];
    renderTab();
    await user.pointer({ keys: "[MouseRight]", target: await screen.findByText("b.example.com") });
    await user.click(await screen.findByRole("menuitem", { name: "Remove" }));
    await vi.waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0]).toEqual({ method: "domains.remove", params: { pattern: "b.example.com", vpn: "" } });
  });

  it("acts on the whole selection when the right-clicked entry is in it", async () => {
    const user = userEvent.setup();
    lists[""] = ["a.example.com", "b.example.com", "c.example.com"];
    renderTab();
    await user.click(await screen.findByText("a.example.com"));
    await user.keyboard("{Shift>}");
    await user.click(screen.getByText("b.example.com"));
    await user.keyboard("{/Shift}");
    await user.pointer({ keys: "[MouseRight]", target: screen.getByText("b.example.com") });
    await user.click(await screen.findByRole("menuitem", { name: "Remove 2 Entries" }));
    await vi.waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0]).toEqual({ method: "domains.set", params: { patterns: ["c.example.com"], vpn: "" } });
  });

  it("copies the selection from the context menu without changing the list", async () => {
    const user = userEvent.setup();
    lists[""] = ["a.example.com", "b.example.com"];
    renderTab();
    await user.pointer({ keys: "[MouseRight]", target: await screen.findByText("a.example.com") });
    await user.click(await screen.findByRole("menuitem", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("a.example.com");
    expect(writes()).toEqual([]);
  });

  it("replaces the list from the text editor, and refuses invalid text", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("a.example.com");
    await user.click(screen.getByRole("button", { name: "List actions" }));
    await user.click(await screen.findByRole("menuitem", { name: /Edit as Text/ }));
    const editor = await screen.findByLabelText("Entries as text");
    expect(editor).toHaveValue("a.example.com\nb.example.com");
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();

    await user.clear(editor);
    await user.type(editor, "# note{Enter}new.example.com{Enter}bad*");
    expect(screen.getByRole("alert")).toHaveTextContent("bad*: Invalid pattern format");
    expect(save).toBeDisabled();

    await user.type(editor, "{Backspace}{Backspace}{Backspace}{Backspace}");
    expect(save).toBeEnabled();
    await user.click(save);
    await vi.waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0]).toEqual({ method: "domains.set", params: { patterns: ["new.example.com"], vpn: "" } });
  });

  it("offers Open in VPN Tab for a VPN list only when the host can switch", async () => {
    const user = userEvent.setup();
    const onOpenVpnTab = vi.fn();
    window.localStorage.setItem("routewise.domains.selectedList", JSON.stringify(AWS));
    renderTab({ onOpenVpnTab });
    await screen.findByText("aws.example.com");
    await user.click(screen.getByRole("button", { name: "List actions" }));
    await user.click(await screen.findByRole("menuitem", { name: "Open in VPN Tab" }));
    expect(onOpenVpnTab).toHaveBeenCalledOnce();
  });
});
