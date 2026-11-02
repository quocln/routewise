import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { listenHelperStatus } from "@/lib/native/shell-feeds";
import { queryKeys } from "./queries";

/**
 * Keeps the status query current from the shell's feed for as long as the caller is
 * mounted. When the shell could not get a status, the query asks for itself, which
 * yields the error as the rest of the app knows it.
 */
export function useStatusFeed(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    let stopped = false;
    let unlisten: (() => void) | undefined;
    void listenHelperStatus((feed) => {
      if (feed.status) {
        queryClient.setQueryData(queryKeys.status, feed.status);
      } else {
        void queryClient.invalidateQueries({ queryKey: queryKeys.status });
      }
    }).then((stop) => {
      if (stopped) stop();
      else unlisten = stop;
    });
    return () => {
      stopped = true;
      unlisten?.();
    };
  }, [queryClient]);
}
