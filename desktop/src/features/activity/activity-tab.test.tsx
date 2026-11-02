import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { resetWrittenForTests } from "@/lib/use-persisted-state";

const replies: Record<string, unknown> = {};
const calls: { method: string; params: unknown }[] = [];
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: (_cmd: string, args: { method: string; params: unknown }) => {
    calls.push(args);
    if (args.method in replies) return Promise.resolve(replies[args.method]);
    return Promise.reject({ kind: "remote", code: -32601, message: "method not found" });
  },
}));

type Handler = (event: unknown) => void;
const streams: Record<string, { params: unknown; emit: Handler }> = {};
const stops: string[] = [];
vi.mock("@/lib/rpc/rpc-stream", () => ({
  subscribeStream: (kind: string, params: unknown, emit: Handler) => {
    streams[kind] = { params, emit };
    return () => stops.push(kind);
  },
}));

// jsdom has no layout, so a real virtualizer would show no rows; render them all instead.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: { count: number; estimateSize: () => number; getItemKey: (i: number) => string }) => ({
    getTotalSize: () => options.count * options.estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: options.count }, (_, index) => ({
        index,
        key: options.getItemKey(index),
        start: index * options.estimateSize(),
        size: options.estimateSize(),
      })),
  }),
}));

const { ActivityTab } = await import("./activity-tab");

beforeEach(() => {
  resetWrittenForTests();
  window.localStorage.clear();
  calls.length = 0;
  stops.length = 0;
  for (const key of Object.keys(streams)) delete streams[key];
  for (const key of Object.keys(replies)) delete replies[key];
  replies["status.get"] = { running: true, vpnConnected: false, routeCount: 0 };
  replies["settings.get"] = {
    useVpnDns: false, allowIpv6: false, allowedVpnClients: [], historyEnabled: true, historyRetentionDays: 7,
  };
  replies["profiles.list"] = [];
});

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ActivityTab />
    </QueryClientProvider>,
  );
}

const entry = (over: Record<string, unknown>) => ({
  id: 1, time: new Date().toISOString(), name: "jira.corp.com", ip: "10.1.2.3", port: 443, proto: "tcp",
  interface: "utun4", vpn: "SG", verdict: "vpn", ...over,
});

describe("ActivityTab", () => {
  it("streams today's connections and shows them", async () => {
    renderTab();
    expect(streams.access.params).toMatchObject({ limit: 500 });
    expect(streams.access.params).toHaveProperty("sinceMs");
    expect(screen.getByText("Loading...")).toBeInTheDocument();
    act(() =>
      streams.access.emit({
        kind: "data",
        initial: true,
        data: { latestId: 2, entries: [entry({ id: 1 }), entry({ id: 2, name: "wiki.sg.io", verdict: "direct", vpn: undefined, list: "routewise-wireguard:sg" })] },
      }),
    );
    const rows = await screen.findAllByTestId("activity-row");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("wiki.sg.io")).toBeInTheDocument();
    expect(within(rows[0]).getByTestId("row-warning")).toHaveTextContent("sg off");
    expect(within(rows[1]).getByText("→ via SG")).toBeInTheDocument();
  });

  it("says history recording is off", async () => {
    replies["settings.get"] = { ...(replies["settings.get"] as object), historyEnabled: false };
    renderTab();
    expect(await screen.findByText("History recording is off. Turn it on in Settings.")).toBeInTheDocument();
  });

  it("switches to DNS, streams events only there, and shows an IPv6 notice", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(screen.getByRole("tab", { name: "DNS" }));
    expect(stops).toContain("access");
    expect(streams.activity.params).toEqual({ limit: 1000 });
    act(() =>
      streams.activity.emit({
        kind: "data",
        initial: true,
        data: {
          latest: 2,
          events: [
            { seq: 1, time: new Date().toISOString(), kind: "route_added", name: "a.com" },
            {
              seq: 2, time: new Date().toISOString(), kind: "dns", name: "wiki.sg.io", list: "wg",
              addresses: [{ ip: "2606:4700::1", verdict: "direct", blocked: true }],
            },
          ],
        },
      }),
    );
    const rows = await screen.findAllByTestId("activity-row");
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByTestId("row-notice")).toHaveTextContent("IPv6 blocked");
    await user.click(screen.getByRole("tab", { name: "Events" }));
    expect(await screen.findByText("a.com")).toBeInTheDocument();
  });

  it("pauses the event stream and clears what is shown", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(screen.getByRole("tab", { name: "Events" }));
    act(() =>
      streams.activity.emit({
        kind: "data", initial: true,
        data: { latest: 1, events: [{ seq: 1, time: new Date().toISOString(), kind: "vpn", name: "SG" }] },
      }),
    );
    expect(await screen.findAllByTestId("activity-row")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Pause" }));
    expect(stops).toContain("activity");
    expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear" }));
    expect(await screen.findByText("No activity yet")).toBeInTheDocument();
  });

  it("confirms before clearing the history, then empties the list", async () => {
    const user = userEvent.setup();
    replies["access.clear"] = { deleted: 1 };
    renderTab();
    act(() => streams.access.emit({ kind: "data", initial: true, data: { latestId: 1, entries: [entry({})] } }));
    await screen.findByTestId("activity-row");
    await waitFor(() => expect(screen.getByRole("button", { name: "Clear History" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Clear History" }));
    expect(calls.some((c) => c.method === "access.clear")).toBe(false);
    expect(await screen.findByText("This permanently deletes every recorded connection.")).toBeInTheDocument();
    const dialog = screen.getByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Clear History" }));
    await waitFor(() => expect(calls.some((c) => c.method === "access.clear")).toBe(true));
    expect(await screen.findByText("No connections recorded in this range")).toBeInTheDocument();
  });

  it("checks a host", async () => {
    const user = userEvent.setup();
    replies["routes.check"] = {
      host: "jira.corp.com",
      matchedPatterns: ["*.corp.com"],
      addresses: [{ ip: "10.1.2.3", verdict: "vpn", interface: "utun4", routedFor: "jira.corp.com" }],
    };
    renderTab();
    await user.click(screen.getByRole("button", { name: "Check host" }));
    await user.type(screen.getByLabelText("Host to check"), "https://jira.corp.com/x{Enter}");
    const result = await screen.findByTestId("host-check-result");
    expect(result).toHaveTextContent("Matches: *.corp.com");
    expect(result).toHaveTextContent("VPN");
    expect(result).toHaveTextContent("utun4 · for jira.corp.com");
    expect(calls.find((c) => c.method === "routes.check")?.params).toEqual({ host: "https://jira.corp.com/x" });
  });

  it("shows a stream error", async () => {
    renderTab();
    act(() => streams.access.emit({ kind: "error", error: { kind: "unavailable", message: "No such file" } }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The helper is not reachable: No such file");
  });
});
