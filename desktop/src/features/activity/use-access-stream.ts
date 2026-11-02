"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Entry as AccessEntry } from "@/lib/api/history.gen";
import type { AccessListParams } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import { subscribeStream } from "@/lib/rpc/rpc-stream";
import { ACCESS_PAGE_SIZE, MAX_KEPT_ENTRIES, appendOlder, mergeAccess } from "./activity-feed";
import { parseTime } from "./activity-event";
import { featureErrorMessage } from "./helper-feature-error";

export interface AccessStream {
  entries: AccessEntry[];
  error: string | null;
  /** True until the first page of the current filters has arrived. */
  isLoading: boolean;
  /** Older rows than the oldest shown may exist and fit under the cap. */
  hasOlder: boolean;
  isLoadingOlder: boolean;
  loadOlder: () => void;
  /** Empties the list after the history was deleted. */
  reset: () => void;
}

/**
 * Loads the recorded connections for `params`, then streams new ones while
 * enabled. Changing `params` (compared by value) starts over.
 */
export function useAccessStream(params: AccessListParams, enabled: boolean): AccessStream {
  const [entries, setEntries] = useState<AccessEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  // The params the first page arrived for; loading lasts until it matches the current ones.
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const [hasOlder, setHasOlder] = useState(false);
  const [isLoadingOlder, setIsLoadingOlder] = useState(false);
  const key = JSON.stringify(params);
  // Bumped whenever the list is replaced, so an older page that was in flight is dropped.
  const generation = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    return subscribeStream("access", JSON.parse(key) as AccessListParams, (event) => {
      if (event.kind === "error") {
        setError(featureErrorMessage(event.error));
        return;
      }
      setError(null);
      if (event.initial) {
        generation.current += 1;
        setLoadedKey(key);
        setHasOlder((event.data.entries ?? []).length >= ACCESS_PAGE_SIZE);
      }
      setEntries((prev) => mergeAccess(prev, event.data, event.initial));
    });
  }, [key, enabled]);

  const loadOlder = useCallback(() => {
    const oldest = entries[entries.length - 1];
    const date = oldest && parseTime(oldest.time);
    if (!oldest || !date || isLoadingOlder) return;
    const started = generation.current;
    setIsLoadingOlder(true);
    rpc("access.list", { ...params, untilMs: Math.ceil(date.getTime()) })
      .then((result) => {
        // New filters or a reset replaced the list while the request was out.
        if (generation.current !== started) return;
        const page = result.entries ?? [];
        const older = page.filter((e) => e.id < oldest.id).length;
        setEntries((prev) => appendOlder(prev, page));
        setHasOlder(older > 0 && page.length >= ACCESS_PAGE_SIZE && entries.length + older < MAX_KEPT_ENTRIES);
        setError(null);
      })
      .catch((e: unknown) => setError(featureErrorMessage(e)))
      .finally(() => setIsLoadingOlder(false));
  }, [entries, params, isLoadingOlder]);

  const reset = useCallback(() => {
    generation.current += 1;
    setEntries([]);
    setHasOlder(false);
    setError(null);
  }, []);

  return { entries, error, isLoading: loadedKey !== key, hasOlder, isLoadingOlder, loadOlder, reset };
}
