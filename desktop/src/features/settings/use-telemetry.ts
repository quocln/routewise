import { useMutation, useQuery, useQueryClient, type UseMutationResult, type UseQueryResult } from "@tanstack/react-query";
import type { SetTelemetryParams, TelemetrySettings } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";

/**
 * The error reporting settings as the app holds them. The DSN is a secret, so
 * it is reduced to whether one is set the moment the helper's answer arrives:
 * the value is never kept in the query cache or shown.
 */
export interface TelemetryView {
  hasDsn: boolean;
  errors: boolean;
  sessions: boolean;
  logs: boolean;
  traces: boolean;
  tracesSampleRate: number;
}

export function toTelemetryView(settings: TelemetrySettings): TelemetryView {
  const { dsn, ...rest } = settings;
  return { ...rest, hasDsn: dsn !== "" };
}

const KEY = ["telemetry.get"] as const;

export function useTelemetry(): UseQueryResult<TelemetryView, RpcError> {
  return useQuery<TelemetryView, RpcError>({
    queryKey: KEY,
    queryFn: async () => toTelemetryView(await rpc("telemetry.get")),
  });
}

/** Saves the fields in `params` (only those change). */
export function useTelemetryMutation(): UseMutationResult<TelemetryView, RpcError, SetTelemetryParams> {
  const queryClient = useQueryClient();
  return useMutation<TelemetryView, RpcError, SetTelemetryParams>({
    mutationFn: async (params) => toTelemetryView(await rpc("telemetry.set", params)),
    onSuccess: (view) => queryClient.setQueryData(KEY, view),
  });
}
