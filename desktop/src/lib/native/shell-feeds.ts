import { isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { StatusResult } from "@/lib/api/types.gen";
import type { SystemStatsSample } from "./native-commands";

/** The shell polls the helper once and pushes each change here and to the tray. */
export const HELPER_STATUS_EVENT = "helper://status";
/** The shell emits each new sample of this computer's figures. */
export const SYSTEM_STATS_EVENT = "system://stats";

/** The helper's status, or null when the shell could not get one. */
export interface HelperStatusFeed {
  status: StatusResult | null;
}

/**
 * Listens to one of the shell's feeds until the returned function is called. A feed is
 * a convenience on top of asking: outside the app, or if listening fails, this is a
 * no-op and the caller's slow refresh keeps it current.
 */
async function listenFeed<T>(event: string, handler: (payload: T) => void): Promise<UnlistenFn> {
  if (!isTauri()) return () => {};
  try {
    return await listen<T>(event, (e) => handler(e.payload));
  } catch {
    return () => {};
  }
}

export function listenHelperStatus(handler: (feed: HelperStatusFeed) => void): Promise<UnlistenFn> {
  return listenFeed(HELPER_STATUS_EVENT, handler);
}

export function listenSystemStats(handler: (sample: SystemStatsSample) => void): Promise<UnlistenFn> {
  return listenFeed(SYSTEM_STATS_EVENT, handler);
}
