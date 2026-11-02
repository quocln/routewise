import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const replies: Record<string, unknown> = {};
const calls: { method: string; params: unknown }[] = [];
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: (_cmd: string, args: { method: string; params: unknown }) => {
    calls.push(args);
    const reply = replies[args.method];
    if (reply instanceof Error) return Promise.reject({ kind: "remote", code: -32000, message: reply.message });
    if (args.method in replies) return Promise.resolve(reply);
    return Promise.reject({ kind: "remote", code: -32601, message: "method not found" });
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

const { RoutesTab } = await import("./routes-tab");

const routes = [
  {
    ip: "10.1.1.1", gateway: "10.8.0.1", interface: "utun5", domain: "app.corp.example.com",
    addedAt: "2026-10-29T10:15:00Z", protected: false, vpn: "SG", clientId: "sg", list: "sg", rule: "*.corp.example.com",
  },
  {
    ip: "10.2.2.2", gateway: "10.9.0.1", interface: "utun6", domain: "",
    addedAt: "2026-10-29T10:16:00Z", protected: true, vpn: "HK", clientId: "hk",
  },
  {
    ip: "3.3.3.3", gateway: "10.8.0.1", interface: "utun5", domain: "db.example.com",
    addedAt: "2026-10-29T10:17:00Z", protected: false, vpn: "SG", clientId: "sg", list: "", rule: "db.example.com",
  },
];

beforeEach(() => {
  calls.length = 0;
  for (const key of Object.keys(replies)) delete replies[key];
  replies["status.get"] = { running: true, vpnConnected: true, routeCount: 3 };
  replies["settings.get"] = {
    useVpnDns: false, allowIpv6: false, historyEnabled: true, historyRetentionDays: 7,
    allowedVpnClients: [{ id: "sg", name: "Singapore" }],
  };
  replies["profiles.list"] = [];
  replies["routes.list"] = routes;
});

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RoutesTab />
    </QueryClientProvider>,
  );
}

const rows = () => screen.getAllByTestId("route-row");

describe("RoutesTab", () => {
  it("lists the routes with the list that added each", async () => {
    renderTab();
    await screen.findByText("app.corp.example.com");
    expect(rows()).toHaveLength(3);
    const first = within(rows()[0]);
    expect(first.getByText("*.corp.example.com")).toBeInTheDocument();
    // The list that added the route and the tunnel it goes through are both Singapore.
    expect(first.getAllByText("Singapore")).toHaveLength(2);
    expect(first.getByText("utun5")).toBeInTheDocument();
    // A VPN DNS server route has no list; a route with no domain shows its address.
    expect(within(rows()[1]).getByText("VPN DNS server")).toBeInTheDocument();
    expect(within(rows()[1]).getAllByText("10.2.2.2")).toHaveLength(2);
    expect(within(rows()[2]).getByText("Any VPN")).toBeInTheDocument();
    expect(within(rows()[1]).getByText("HK")).toBeInTheDocument();
  });

  it("filters by search text, and says when nothing matches", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("app.corp.example.com");
    await user.type(screen.getByLabelText("Search routes"), "db.");
    expect(rows()).toHaveLength(1);
    await user.clear(screen.getByLabelText("Search routes"));
    await user.type(screen.getByLabelText("Search routes"), "zzz");
    expect(screen.queryAllByTestId("route-row")).toHaveLength(0);
    expect(screen.getByText("No matching routes")).toBeInTheDocument();
  });

  it("summarises tunnels and filters by the chosen one", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("app.corp.example.com");
    const chips = within(screen.getByTestId("via-chips"));
    expect(chips.getByRole("button", { name: /^All VPNs\s*3$/ })).toHaveAttribute("aria-pressed", "true");
    await user.click(chips.getByRole("button", { name: /^Singapore\s*utun5 · 2 routes$/ }));
    expect(rows()).toHaveLength(2);
    await user.click(chips.getByRole("button", { name: /^HK\s*utun6 · 1 route$/ }));
    expect(rows()).toHaveLength(1);
    // Choosing the active chip again clears the filter.
    await user.click(chips.getByRole("button", { name: /^HK/ }));
    expect(rows()).toHaveLength(3);
  });

  it("explains an empty table", async () => {
    replies["routes.list"] = [];
    renderTab();
    expect(await screen.findByText("No routes")).toBeInTheDocument();
    expect(screen.getByText(/Routes appear when a VPN is connected/)).toBeInTheDocument();
    expect(screen.queryByTestId("via-chips")).toBeNull();
  });

  it("shows the helper's error", async () => {
    replies["routes.list"] = new Error("helper busy");
    renderTab();
    expect(await screen.findByRole("alert")).toHaveTextContent("helper busy");
  });

  it("refreshes on demand", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("app.corp.example.com");
    const before = calls.filter((c) => c.method === "routes.list").length;
    await user.click(screen.getByRole("button", { name: "Refresh routes" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "routes.list").length).toBeGreaterThan(before));
  });

  it("checks a host with the shared panel, always visible", async () => {
    const user = userEvent.setup();
    replies["routes.check"] = {
      host: "app.corp.example.com", matchedPatterns: ["*.corp.example.com"],
      addresses: [{ ip: "10.1.1.1", verdict: "vpn", interface: "utun5" }],
    };
    renderTab();
    await user.type(screen.getByLabelText("Host to check"), "app.corp.example.com");
    await user.click(screen.getByRole("button", { name: "Check" }));
    expect(await screen.findByTestId("host-check-result")).toHaveTextContent("VPN");
    expect(calls.find((c) => c.method === "routes.check")?.params).toEqual({ host: "app.corp.example.com" });
  });
});
