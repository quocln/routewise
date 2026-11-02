import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// A plain function, not vi.fn(): the test runner reports a rejection returned
// by a spy as unhandled, while the real `invoke` is awaited by the client.
type Answer = () => Promise<unknown>;
let answer: Answer = () => Promise.resolve(undefined);
const calls: unknown[][] = [];
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => {
    calls.push(args);
    return answer();
  },
  isTauri: () => true,
}));

const { StatusHeader } = await import("./status-header");

function renderHeader() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <StatusHeader />
    </QueryClientProvider>,
  );
}

describe("StatusHeader", () => {
  beforeEach(() => {
    calls.length = 0;
  });

  it("shows the helper's live status", async () => {
    answer = () =>
      Promise.resolve({
        running: true,
        vpnConnected: true,
        routeCount: 3,
        tunnels: [{ interface: "utun4", client: { id: "/a", name: "AWS VPN" }, routeCount: 3 }],
      });
    renderHeader();
    expect(await screen.findByText("VPN connected")).toBeInTheDocument();
    expect(screen.getByTestId("status-detail")).toHaveTextContent("AWS VPN · 3 routes");
    expect(calls[0]).toEqual(["rpc", { method: "status.get", params: undefined }]);
  });

  it("says so when the helper is not running", async () => {
    answer = () => Promise.reject({ kind: "unavailable", message: "No such file or directory" });
    renderHeader();
    expect(await screen.findByText("Helper not running")).toBeInTheDocument();
  });
});
