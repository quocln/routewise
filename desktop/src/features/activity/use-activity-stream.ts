"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import { subscribeStream } from "@/lib/rpc/rpc-stream";
import { mergeActivity } from "./activity-feed";
import { featureErrorMessage } from "./helper-feature-error";

export interface ActivityStream {
  events: ActivityEvent[];
  /** The last stream error, cleared by the next successful poll. */
  error: string | null;
  /** Empties the list; cleared events do not return while the helper keeps running. */
  clear: () => void;
}

interface Options {
  /** Streams only while true: the helper is polled only while a view needs the events. */
  enabled: boolean;
  /** Stops polling without forgetting the events; resuming catches up. */
  paused?: boolean;
  limit?: number;
}

/** Streams the helper's activity log while enabled. */
export function useActivityStream({ enabled, paused = false, limit = 1000 }: Options): ActivityStream {
  const [state, setState] = useState<{ events: ActivityEvent[]; error: string | null }>({ events: [], error: null });
  // The newest seq the user cleared; the helper restarting resets numbering and the floor with it.
  const floor = useRef(0);
  const active = enabled && !paused;

  useEffect(() => {
    if (!active) return;
    return subscribeStream("activity", { limit }, (event) => {
      if (event.kind === "error") {
        setState((s) => ({ ...s, error: featureErrorMessage(event.error) }));
        return;
      }
      if (event.initial && event.data.latest < floor.current) floor.current = 0;
      setState((s) => ({ events: mergeActivity(s.events, event.data, event.initial, floor.current), error: null }));
    });
  }, [active, limit]);

  const clear = useCallback(() => {
    setState((s) => {
      floor.current = Math.max(floor.current, s.events[0]?.seq ?? 0);
      return { ...s, events: [] };
    });
  }, []);

  return { events: state.events, error: state.error, clear };
}
