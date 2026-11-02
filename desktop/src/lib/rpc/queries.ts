import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import type { Settings, StatusResult } from "@/lib/api/types.gen";
import { rpc } from "./rpc-client";
import type { RpcError } from "./rpc-error";

/**
 * The shell pushes each change of status (see useStatusFeed), so this only catches what
 * a lost event would leave behind.
 */
const STATUS_RESYNC_MS = 30_000;

export const queryKeys = {
  status: ["status.get"] as const,
  settings: ["settings.get"] as const,
};

/** The helper's status, kept current by the shell's feed while the window is open. */
export function useStatus(): UseQueryResult<StatusResult, RpcError> {
  return useQuery<StatusResult, RpcError>({
    queryKey: queryKeys.status,
    queryFn: () => rpc("status.get"),
    refetchInterval: STATUS_RESYNC_MS,
    refetchIntervalInBackground: false,
  });
}

/** The settings the app can change. */
export function useSettings(): UseQueryResult<Settings, RpcError> {
  return useQuery<Settings, RpcError>({
    queryKey: queryKeys.settings,
    queryFn: () => rpc("settings.get"),
  });
}
