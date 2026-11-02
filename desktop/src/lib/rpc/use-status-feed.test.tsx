import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { queryKeys } from "./queries";
import { useStatusFeed } from "./use-status-feed";

let emit: ((event: { payload: unknown }) => void) | undefined;
const stop = vi.fn();
let listenFails = false;

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true, invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (_name: string, handler: (event: { payload: unknown }) => void) => {
    if (listenFails) return Promise.reject(new Error("no events"));
    emit = handler;
    return Promise.resolve(stop);
  },
}));

function Probe() {
  useStatusFeed();
  return null;
}

function mount() {
  const client = new QueryClient();
  const view = render(
    <QueryClientProvider client={client}>
      <Probe />
    </QueryClientProvider>,
  );
  return { client, view };
}

describe("useStatusFeed", () => {
  beforeEach(() => {
    emit = undefined;
    listenFails = false;
    stop.mockClear();
  });

  it("puts each status from the shell where the app reads it", async () => {
    const { client } = mount();
    await waitFor(() => expect(emit).toBeDefined());
    emit?.({ payload: { status: { running: true, routeCount: 7 } } });
    expect(client.getQueryData(queryKeys.status)).toEqual({ running: true, routeCount: 7 });
  });

  it("asks for itself when the shell has no status, so the error reaches the app", async () => {
    const { client } = mount();
    await waitFor(() => expect(emit).toBeDefined());
    const invalidate = vi.spyOn(client, "invalidateQueries");
    emit?.({ payload: { status: null } });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.status });
  });

  it("stops listening when it unmounts", async () => {
    const { view } = mount();
    await waitFor(() => expect(emit).toBeDefined());
    await Promise.resolve();
    view.unmount();
    await waitFor(() => expect(stop).toHaveBeenCalled());
  });

  it("does nothing when events are not available", async () => {
    listenFails = true;
    const { client, view } = mount();
    await Promise.resolve();
    expect(client.getQueryData(queryKeys.status)).toBeUndefined();
    view.unmount();
  });
});
