import { useQueries, useQuery, type UseQueryResult } from "@tanstack/react-query";
import type { ProfileInfo } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";
import { useStatus } from "@/lib/rpc/queries";

/** How often the profile list refreshes while the tab is in front. */
const PROFILES_REFRESH_MS = 2000;

export const vpnKeys = {
  profiles: ["profiles.list"] as const,
  /** The domain list of a VPN client; an empty id is the "Any VPN" list. */
  domains: (vpn: string) => ["domains.list", { vpn }] as const,
};

/** The built-in profiles, refreshed while the tab is in front. */
export function useProfiles(): UseQueryResult<ProfileInfo[], RpcError> {
  return useQuery<ProfileInfo[], RpcError>({
    queryKey: vpnKeys.profiles,
    queryFn: () => rpc("profiles.list"),
    refetchInterval: PROFILES_REFRESH_MS,
    refetchIntervalInBackground: false,
  });
}

/** Whether the helper answered its last status request. */
export function useHelperReachable(): boolean {
  const { data, error } = useStatus();
  return data !== undefined && !error?.isUnavailable;
}

/** Entry count per domain list id; a list not counted yet is absent. */
export function useDomainCounts(clientIds: readonly string[]): Record<string, number> {
  return useQueries({
    queries: clientIds.map((id) => ({
      queryKey: vpnKeys.domains(id),
      queryFn: () => rpc("domains.list", { vpn: id }),
    })),
    combine: (results) => {
      const counts: Record<string, number> = {};
      results.forEach((result, index) => {
        if (result.data) counts[clientIds[index]] = result.data.length;
      });
      return counts;
    },
  });
}
