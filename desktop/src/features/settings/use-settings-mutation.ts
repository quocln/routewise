import { useMutation, useQueryClient, type UseMutationResult } from "@tanstack/react-query";
import type { SetSettingsParams, Settings } from "@/lib/api/types.gen";
import { queryKeys } from "@/lib/rpc/queries";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";

/** Saves a change to the helper's settings; the answer is the settings as they now are. */
export function useSettingsMutation(): UseMutationResult<Settings, RpcError, SetSettingsParams> {
  const queryClient = useQueryClient();
  return useMutation<Settings, RpcError, SetSettingsParams>({
    mutationFn: (params) => rpc("settings.set", params),
    onSuccess: (settings) => queryClient.setQueryData(queryKeys.settings, settings),
  });
}
