import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
const listen = vi.fn();
const unlisten = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true, invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: (...args: unknown[]) => listen(...args) }));

const { NAVIGATE_TAB_EVENT, useShellNavigation } = await import("./use-shell-navigation");

let emit: ((payload: { tab: string }) => void) | undefined;

beforeEach(() => {
  invoke.mockReset().mockResolvedValue(null);
  unlisten.mockReset();
  emit = undefined;
  listen.mockReset().mockImplementation((_name: string, handler: (e: { payload: { tab: string } }) => void) => {
    emit = (payload) => handler({ payload });
    return Promise.resolve(unlisten);
  });
});

describe("useShellNavigation", () => {
  it("applies the tab the shell remembered for a freshly created window", async () => {
    invoke.mockResolvedValue("settings");
    const onTab = vi.fn();
    renderHook(() => useShellNavigation(onTab));
    await waitFor(() => expect(onTab).toHaveBeenCalledWith("settings"));
    expect(listen).toHaveBeenCalledWith(NAVIGATE_TAB_EVENT, expect.any(Function));
    expect(invoke).toHaveBeenCalledWith("take_pending_tab", undefined);
  });

  it("does nothing when no tab is remembered", async () => {
    const onTab = vi.fn();
    renderHook(() => useShellNavigation(onTab));
    await waitFor(() => expect(invoke).toHaveBeenCalled());
    expect(onTab).not.toHaveBeenCalled();
  });

  it("follows a request to an open window and clears the remembered tab", async () => {
    const onTab = vi.fn();
    renderHook(() => useShellNavigation(onTab));
    await waitFor(() => expect(emit).toBeDefined());
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    emit?.({ tab: "activity" });
    expect(onTab).toHaveBeenCalledWith("activity");
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
  });

  it("stops listening on unmount", async () => {
    const { unmount } = renderHook(() => useShellNavigation(vi.fn()));
    await waitFor(() => expect(emit).toBeDefined());
    unmount();
    await waitFor(() => expect(unlisten).toHaveBeenCalled());
  });

  it("ignores a failed read of the remembered tab", async () => {
    invoke.mockRejectedValue("boom");
    const onTab = vi.fn();
    renderHook(() => useShellNavigation(onTab));
    await waitFor(() => expect(invoke).toHaveBeenCalled());
    expect(onTab).not.toHaveBeenCalled();
  });
});
