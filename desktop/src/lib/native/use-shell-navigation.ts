import { useEffect } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { nativeInvoke } from "./native-invoke";

/** The shell emits this when a tray item asks the open window for a tab. */
export const NAVIGATE_TAB_EVENT = "navigate://tab";

/**
 * Follows the tray's requests to show a tab for as long as the caller is
 * mounted. The shell remembers the requested tab until it is read, because a
 * window created for the request has no listener yet: the listener is
 * registered first, then the remembered tab is read once, so a request is seen
 * either way. Every request is also read back, which clears the memory.
 * Outside the app there is no shell and nothing happens.
 */
export function useShellNavigation(onTab: (tab: string) => void): void {
  useEffect(() => {
    if (!isTauri()) return;
    let stopped = false;
    let unlisten: (() => void) | undefined;
    const apply = (tab: string | null) => {
      if (!stopped && tab) onTab(tab);
    };
    const takePending = () => nativeInvoke<string | null>("take_pending_tab").then(apply, () => {});

    listen<{ tab: string }>(NAVIGATE_TAB_EVENT, (event) => {
      apply(event.payload.tab);
      void takePending();
    })
      .then((stop) => {
        if (stopped) {
          stop();
          return;
        }
        unlisten = stop;
        return takePending();
      })
      .catch(() => {
        // Without the event the tray still opens the window, on its last tab.
      });
    return () => {
      stopped = true;
      unlisten?.();
    };
    // `onTab` is read once: callers pass an inline function.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
