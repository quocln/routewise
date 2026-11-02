import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useRef, useState } from "react";
import type { ProfileImportParams, ProfileInfo, ProfileUpdateParams } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import { queryKeys } from "@/lib/rpc/queries";
import { profileKind } from "./vpn-format";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { vpnKeys } from "./vpn-queries";

/** Adds or removes `key` from a keyed record without mutating it. */
function withKey<T>(record: Record<string, T>, key: string, value: T | undefined): Record<string, T> {
  const next = { ...record };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

export interface ProfileActions {
  /** Requested connect state per profile id while the change is in flight. */
  pendingConnect: Record<string, boolean>;
  pendingAutoConnect: Record<string, boolean>;
  /** Profile ids with a rename, remove or credential change in flight. */
  busy: ReadonlySet<string>;
  /** The last failure of a row action; cleared by the next successful one. */
  actionError: string | null;
  setConnected: (profile: ProfileInfo, connect: boolean) => Promise<void>;
  setAutoConnect: (profile: ProfileInfo, enabled: boolean) => Promise<void>;
  rename: (profile: ProfileInfo, name: string) => Promise<void>;
  remove: (profile: ProfileInfo) => Promise<void>;
  /** Imports a profile and resolves to its id. Rejects with the helper's error. */
  importProfile: (params: ProfileImportParams) => Promise<string>;
  /** Replaces or adds a profile's WireGuard config or Outline key. Rejects with the helper's error. */
  setSecret: (profile: ProfileInfo, secret: string) => Promise<void>;
}

/**
 * The actions of the built-in VPN list, with the in-flight changes the
 * controls show until the helper confirms them.
 *
 * Secrets (a WireGuard config, an Outline key) pass through `importProfile`
 * and `setSecret` into the request params only: never into state, query keys,
 * logs or error messages.
 */
export function useProfileActions(): ProfileActions {
  const queryClient = useQueryClient();
  const [pendingConnect, setPendingConnect] = useState<Record<string, boolean>>({});
  const [pendingAutoConnect, setPendingAutoConnect] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  const [actionError, setActionError] = useState<string | null>(null);
  // State is stale inside a handler that runs twice before a render; these are not.
  const switching = useRef(new Set<string>());
  const switchingAuto = useRef(new Set<string>());
  const working = useRef(new Set<string>());

  /** Re-reads what a change may have touched, waiting for the new profile list. */
  const refresh = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: vpnKeys.profiles }),
      queryClient.invalidateQueries({ queryKey: queryKeys.status }),
    ]);
  }, [queryClient]);

  /** Built-in profiles are allowed clients with domain lists of their own. */
  const refreshMembership = useCallback(async () => {
    await Promise.all([
      refresh(),
      queryClient.invalidateQueries({ queryKey: queryKeys.settings }),
      queryClient.invalidateQueries({ queryKey: ["domains.list"] }),
    ]);
  }, [queryClient, refresh]);

  const setConnected = useCallback(
    async (profile: ProfileInfo, connect: boolean) => {
      if (switching.current.has(profile.id)) return;
      switching.current.add(profile.id);
      setPendingConnect((p) => withKey(p, profile.id, connect));
      try {
        await rpc(connect ? "profiles.connect" : "profiles.disconnect", { id: profile.id });
        setActionError(null);
      } catch (error) {
        setActionError(
          `Could not ${connect ? "connect" : "disconnect"} ${profile.name || profile.id}: ${helperFeatureErrorMessage(error)}`,
        );
      }
      await refresh();
      switching.current.delete(profile.id);
      setPendingConnect((p) => withKey(p, profile.id, undefined));
    },
    [refresh],
  );

  const setAutoConnect = useCallback(
    async (profile: ProfileInfo, enabled: boolean) => {
      if (switchingAuto.current.has(profile.id)) return;
      switchingAuto.current.add(profile.id);
      setPendingAutoConnect((p) => withKey(p, profile.id, enabled));
      try {
        await rpc("profiles.update", { id: profile.id, autoConnect: enabled });
        setActionError(null);
      } catch (error) {
        setActionError(
          `Could not change auto-connect for ${profile.name || profile.id}: ${helperFeatureErrorMessage(error)}`,
        );
      }
      await refresh();
      switchingAuto.current.delete(profile.id);
      setPendingAutoConnect((p) => withKey(p, profile.id, undefined));
    },
    [refresh],
  );

  /** Runs a change that locks the profile's controls until it settles. */
  const whileBusy = useCallback(
    async (profile: ProfileInfo, change: () => Promise<void>, failure: string, after: () => Promise<void>) => {
      if (working.current.has(profile.id)) return;
      working.current.add(profile.id);
      setBusy(new Set(working.current));
      try {
        await change();
        setActionError(null);
      } catch (error) {
        setActionError(`${failure}: ${helperFeatureErrorMessage(error)}`);
      }
      await after();
      working.current.delete(profile.id);
      setBusy(new Set(working.current));
    },
    [],
  );

  const rename = useCallback(
    async (profile: ProfileInfo, name: string) => {
      const trimmed = name.trim();
      if (trimmed === "" || trimmed === profile.name) return;
      const params: ProfileUpdateParams = { id: profile.id, name: trimmed };
      await whileBusy(
        profile,
        async () => void (await rpc("profiles.update", params)),
        `Could not rename ${profile.name || profile.id}`,
        refresh,
      );
    },
    [refresh, whileBusy],
  );

  const remove = useCallback(
    (profile: ProfileInfo) =>
      whileBusy(
        profile,
        async () => void (await rpc("profiles.remove", { id: profile.id })),
        `Could not remove ${profile.name || profile.id}`,
        refreshMembership,
      ),
    [refreshMembership, whileBusy],
  );

  const importProfile = useCallback(
    async (params: ProfileImportParams) => {
      const { id } = await rpc("profiles.import", params);
      await refreshMembership();
      return id;
    },
    [refreshMembership],
  );

  const setSecret = useCallback(
    async (profile: ProfileInfo, secret: string) => {
      const kind = profileKind(profile);
      if (kind === "unknown") throw new Error("This profile type is not supported by this version of RouteWise.");
      const params: ProfileUpdateParams =
        kind === "wireguard" ? { id: profile.id, wireguardConfig: secret } : { id: profile.id, accessKey: secret };
      working.current.add(profile.id);
      setBusy(new Set(working.current));
      try {
        await rpc("profiles.update", params);
        await refresh();
      } finally {
        working.current.delete(profile.id);
        setBusy(new Set(working.current));
      }
    },
    [refresh],
  );

  return {
    pendingConnect,
    pendingAutoConnect,
    busy,
    actionError,
    setConnected,
    setAutoConnect,
    rename,
    remove,
    importProfile,
    setSecret,
  };
}
