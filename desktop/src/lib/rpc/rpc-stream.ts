import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AccessListParams, AccessListResult, ActivityParams, ActivityResult } from "@/lib/api/types.gen";
import type { RpcErrorPayload } from "./rpc-error";

/** The helper lists the Rust core can stream, with their params and poll result. */
export interface RpcStreams {
  activity: { params: Pick<ActivityParams, "limit">; data: ActivityResult };
  access: { params: Omit<AccessListParams, "afterId" | "waitMs">; data: AccessListResult };
}

export type RpcStreamKind = keyof RpcStreams;

/** What the Rust core emits for a stream (`StreamEvent` in `rpc/streams.rs`). */
export type RpcStreamEvent<K extends RpcStreamKind> =
  | { kind: "data"; initial: boolean; data: RpcStreams[K]["data"] }
  | { kind: "error"; error: RpcErrorPayload };

const EVENT_PREFIX = "rpc-stream://";

// Start and stop run strictly in the order they were requested, so a view that
// unmounts and remounts at once (React strict mode does) cannot have the old
// view's stop cancel the new view's stream.
let queue: Promise<void> = Promise.resolve();
function enqueue(task: () => Promise<void>): void {
  queue = queue.then(task, task);
}

/**
 * Starts streaming a helper list and calls `onEvent` for each event. The Rust
 * core polls only until the returned function is called. Subscribing again to
 * the same kind replaces the previous stream.
 */
export function subscribeStream<K extends RpcStreamKind>(
  kind: K,
  params: RpcStreams[K]["params"],
  onEvent: (event: RpcStreamEvent<K>) => void,
): () => void {
  let stopped = false;
  let unlisten: UnlistenFn | undefined;

  // Failures to reach the Rust core itself are reported like any unreachable helper.
  const fail = (error: unknown) =>
    onEvent({
      kind: "error",
      error: { kind: "unavailable", message: error instanceof Error ? error.message : String(error) },
    });

  enqueue(async () => {
    if (stopped) return;
    if (!isTauri()) {
      fail(new Error("not running inside the RouteWise app"));
      return;
    }
    try {
      unlisten = await listen<RpcStreamEvent<K>>(EVENT_PREFIX + kind, (e) => onEvent(e.payload));
      await invoke("stream_start", { stream: kind, params });
    } catch (error) {
      fail(error);
    }
  });

  return () => {
    if (stopped) return;
    stopped = true;
    enqueue(async () => {
      unlisten?.();
      if (!isTauri()) return;
      try {
        await invoke("stream_stop", { stream: kind });
      } catch {
        // The stream is gone either way; there is nothing to recover.
      }
    });
  };
}
