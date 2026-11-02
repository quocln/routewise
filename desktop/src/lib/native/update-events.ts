import { isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UpdateInfo } from "./native-commands";

/** The shell emits this when its 24 h background check finds a newer release. */
export const UPDATES_AVAILABLE_EVENT = "updates://available";

/**
 * Calls `handler` for each background update finding until the returned
 * function is called. Outside the app nothing is emitted, so it resolves to a
 * no-op.
 */
export async function listenUpdatesAvailable(handler: (info: UpdateInfo) => void): Promise<() => void> {
  if (!isTauri()) return () => {};
  return listen<UpdateInfo>(UPDATES_AVAILABLE_EVENT, (event) => handler(event.payload));
}
