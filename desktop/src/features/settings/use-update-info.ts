import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listenUpdatesAvailable } from "@/lib/native/update-events";
import { updateLastResult, type UpdateInfo } from "@/lib/native/native-commands";
import { PREFS_KEY } from "./use-preferences";

/** Where the newest update finding lives, whether a check or the shell's background check made it. */
export const UPDATE_INFO_KEY = ["updates.info"] as const;

/** The newest finding of an update check, or undefined before any. */
export function useUpdateInfo(): UpdateInfo | undefined {
  const query = useQuery<UpdateInfo | null>({
    queryKey: UPDATE_INFO_KEY,
    // Filled by checks and by the listener; there is nothing to fetch.
    queryFn: () => null,
    enabled: false,
    staleTime: Infinity,
  });
  return query.data ?? undefined;
}

/** Keeps the finding current with the shell's background checks for as long as the caller is mounted. */
export function useUpdateAvailableListener(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    let stopped = false;
    let unlisten: (() => void) | undefined;
    // A check that ran while no window listened (or before this one opened).
    updateLastResult()
      .then((last) => {
        if (last && !stopped) {
          queryClient.setQueryData<UpdateInfo | null>(UPDATE_INFO_KEY, (current) => current ?? last);
          void queryClient.invalidateQueries({ queryKey: PREFS_KEY });
        }
      })
      .catch(() => {
        // Without it only the next check shows a finding.
      });
    listenUpdatesAvailable((info) => {
      queryClient.setQueryData(UPDATE_INFO_KEY, info);
      // The background check recorded its time.
      void queryClient.invalidateQueries({ queryKey: PREFS_KEY });
    })
      .then((stop) => {
        if (stopped) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // Without the event the Check for Updates button still works.
      });
    return () => {
      stopped = true;
      unlisten?.();
    };
  }, [queryClient]);
}
