import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  helperInstall,
  helperServiceStatus,
  helperUninstall,
  type HelperServiceStatus,
} from "@/lib/native/native-commands";
import { isCancelled, type NativeError } from "@/lib/native/native-error";
import { queryKeys } from "@/lib/rpc/queries";

const SERVICE_KEY = ["native", "helper-service"] as const;

export type HelperAction = "install" | "uninstall";

export interface HelperServiceState {
  /** The launchd service as the OS has it; undefined until known or when the shell cannot tell (outside the app). */
  service: HelperServiceStatus | undefined;
  /** The action in progress, if any. */
  pending: HelperAction | undefined;
  /** Why the last action failed. A declined administrator prompt is not a failure. */
  error: string | null;
  run: (action: HelperAction) => void;
}

/**
 * Whether the helper daemon is installed and running, and the actions that
 * change that. Install doubles as reinstall. Both ask for an administrator
 * password; backing out of it leaves everything as it was and shows nothing.
 */
export function useHelperService(): HelperServiceState {
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: SERVICE_KEY, queryFn: helperServiceStatus, retry: false });
  const action = useMutation<null, NativeError, HelperAction>({
    mutationFn: (kind) => (kind === "install" ? helperInstall() : helperUninstall()),
    onSettled: () => {
      // The helper came or went: what it answers, and what the OS says, may all differ now.
      for (const key of [SERVICE_KEY, queryKeys.status, queryKeys.settings]) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
    },
  });
  return {
    service: status.data,
    pending: action.isPending ? action.variables : undefined,
    error: action.isError && !isCancelled(action.error) ? action.error.message : null,
    run: (kind) => action.mutate(kind),
  };
}
