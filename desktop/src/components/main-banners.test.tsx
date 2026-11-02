import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const replies: Record<string, unknown> = {};
const calls: { method: string; params: unknown }[] = [];
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: (_cmd: string, args: { method: string; params: unknown }) => {
    calls.push(args);
    return args.method in replies
      ? Promise.resolve(replies[args.method])
      : Promise.reject({ kind: "remote", code: -32601, message: "method not found" });
  },
}));

const { MainBanners } = await import("./main-banners");

const pending = { interface: "utun9", client: { id: "/Applications/Other.app", name: "Other" } };
const settings = { useVpnDns: false, allowIpv6: false, allowedVpnClients: [] };

beforeEach(() => {
  calls.length = 0;
  for (const key of Object.keys(replies)) delete replies[key];
  replies["settings.get"] = settings;
});

function renderBanners() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MainBanners />
    </QueryClientProvider>,
  );
}

describe("MainBanners", () => {
  it("offers to manage a detected VPN", async () => {
    replies["status.get"] = { running: true, vpnConnected: false, routeCount: 0, pendingVpns: [pending] };
    replies["vpn.setAllowed"] = settings;
    renderBanners();
    expect(await screen.findByText(/Other VPN on utun9 detected/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Manage this VPN" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "vpn.setAllowed")).toHaveLength(1));
    expect(calls.find((c) => c.method === "vpn.setAllowed")?.params).toEqual({
      clientId: pending.client.id,
      allowed: true,
    });
  });

  it("reads the single-VPN field of an older helper", async () => {
    replies["status.get"] = { running: true, vpnConnected: false, routeCount: 0, pendingVpn: pending };
    renderBanners();
    expect(await screen.findByText(/Other VPN on utun9 detected/)).toBeInTheDocument();
  });

  it("cannot manage a VPN whose client is unknown", async () => {
    replies["status.get"] = {
      running: true, vpnConnected: false, routeCount: 0,
      pendingVpns: [{ interface: "utun9", client: { id: "", name: "" } }],
    };
    renderBanners();
    expect(await screen.findByRole("button", { name: "Manage this VPN" })).toBeDisabled();
    expect(screen.getByText(/could not identify the client/)).toBeInTheDocument();
  });

  it("shows nothing when no VPN is pending", async () => {
    replies["status.get"] = { running: true, vpnConnected: false, routeCount: 0 };
    const { container } = renderBanners();
    await waitFor(() => expect(calls.some((c) => c.method === "status.get")).toBe(true));
    expect(container).toBeEmptyDOMElement();
  });
});
