import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef } from "react";
import type { ProfileInfo } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";
import { useSettings, useStatus } from "@/lib/rpc/queries";
import {
  allowedClients,
  buildListItems,
  countListIds,
  type DomainListItem,
} from "./domain-lists";

/** How often built-in profile states refresh while the window is visible. */
const PROFILES_REFRESH_MS = 3000;

/** Prefix of every list's entries query; invalidate it to reload all lists (for example after a config import). */
export const DOMAIN_LISTS_KEY = ["domains.list"] as const;
export const domainListKey = (vpn: string) => [...DOMAIN_LISTS_KEY, vpn] as const;

/** One list's entries, sorted. Shared by the sidebar counts and the entries pane. */
export function domainListQuery(vpn: string) {
  return {
    queryKey: domainListKey(vpn),
    queryFn: async (): Promise<string[]> => {
      const domains = await rpc("domains.list", { vpn });
      return domains.map((d) => d.pattern).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    },
  };
}

/** The built-in profiles, refreshed while the window is in front. */
function useProfiles() {
  return useQuery<ProfileInfo[], RpcError>({
    queryKey: ["profiles.list"],
    queryFn: () => rpc("profiles.list"),
    refetchInterval: PROFILES_REFRESH_MS,
    refetchIntervalInBackground: false,
  });
}

export interface DomainLists {
  items: DomainListItem[];
  /** Entry count per list id; a list missing here has not been counted yet. */
  counts: Record<string, number>;
  /** False until the allowed clients are known, so the first render does not show only "Any VPN". */
  isReady: boolean;
  isHelperConnected: boolean;
  status: ReturnType<typeof useStatus>["data"];
}

/** Every domain list with its state and entry count. */
export function useDomainLists(): DomainLists {
  const settings = useSettings();
  const profiles = useProfiles();
  const status = useStatus();
  const queryClient = useQueryClient();

  const profileList = profiles.data;
  const items = useMemo(
    () => buildListItems(allowedClients(settings.data), profileList ?? [], status.data),
    [settings.data, profileList, status.data],
  );
  const ids = useMemo(() => countListIds(items, profileList ?? []), [items, profileList]);
  const countQueries = useQueries({ queries: ids.map(domainListQuery) });

  const counts = useMemo(() => {
    const result: Record<string, number> = {};
    ids.forEach((id, index) => {
      const data = countQueries[index]?.data;
      if (data) result[id] = data.length;
    });
    return result;
  }, [ids, countQueries]);

  const isHelperConnected = !(status.isError && status.error.isUnavailable);

  // Lists loaded before the helper went away may be stale once it is back.
  const wasConnected = useRef(isHelperConnected);
  useEffect(() => {
    if (isHelperConnected && !wasConnected.current) {
      void queryClient.invalidateQueries({ queryKey: DOMAIN_LISTS_KEY });
    }
    wasConnected.current = isHelperConnected;
  }, [isHelperConnected, queryClient]);

  return { items, counts, isReady: !settings.isPending, isHelperConnected, status: status.data };
}
