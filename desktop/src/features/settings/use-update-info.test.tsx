import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import type { UpdateInfo } from "@/lib/native/native-commands";

let emit: ((info: UpdateInfo) => void) | undefined;
const unlisten = vi.fn();
vi.mock("@/lib/native/update-events", () => ({
  listenUpdatesAvailable: (handler: (info: UpdateInfo) => void) => {
    emit = handler;
    return Promise.resolve(unlisten);
  },
}));

const lastResult = vi.fn<() => Promise<UpdateInfo | null>>();
vi.mock("@/lib/native/native-commands", () => ({ updateLastResult: () => lastResult() }));

const { useUpdateAvailableListener, useUpdateInfo } = await import("./use-update-info");

const info: UpdateInfo = {
  currentVersion: "0.1.0",
  latestVersion: "0.2.0",
  updateAvailable: true,
  releaseUrl: "https://github.com/quocln/routewise/releases/tag/v0.2.0",
  publishedAt: null,
  notes: null,
};

function setup() {
  const client = new QueryClient();
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(
    () => {
      useUpdateAvailableListener();
      return useUpdateInfo();
    },
    { wrapper },
  );
}

describe("update finding", () => {
  it("shows a finding the shell made while no window was open", async () => {
    lastResult.mockResolvedValue(info);
    const { result } = setup();
    await waitFor(() => expect(result.current).toEqual(info));
  });

  it("stays empty when the shell has no finding or cannot answer", async () => {
    lastResult.mockResolvedValueOnce(null);
    const first = setup();
    await waitFor(() => expect(lastResult).toHaveBeenCalled());
    expect(first.result.current).toBeUndefined();
    lastResult.mockRejectedValueOnce(new Error("no shell"));
    const second = setup();
    await waitFor(() => expect(lastResult).toHaveBeenCalledTimes(2));
    expect(second.result.current).toBeUndefined();
  });

  it("follows the shell's background check and stops listening on unmount", async () => {
    lastResult.mockResolvedValue(null);
    const client = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const { result, unmount } = renderHook(
      () => {
        useUpdateAvailableListener();
        return useUpdateInfo();
      },
      { wrapper },
    );
    expect(result.current).toBeUndefined();
    await waitFor(() => expect(emit).toBeDefined());
    act(() => emit?.(info));
    await waitFor(() => expect(result.current).toEqual(info));
    unmount();
    await waitFor(() => expect(unlisten).toHaveBeenCalled());
  });
});
