"use client";

import { FileDownIcon, KeyRoundIcon } from "lucide-react";
import { useState } from "react";
import type { ProfileInfo, StatusResult } from "@/lib/api/types.gen";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { BuiltInProfileCard } from "./built-in-profile-card";
import { ProfileSheetHost, type ProfileSheet } from "./profile-sheets";
import { useProfileActions } from "./use-profile-actions";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { profileClientId, profileKind } from "./vpn-format";
import { useDomainCounts, useHelperReachable, useProfiles } from "./vpn-queries";
import { useWireGuardFilePicker } from "./wireguard-file-picker";

interface Props {
  status: StatusResult | undefined;
  /** Opens the Domains tab on a VPN's list; absent when the window cannot. */
  onEditDomains?: (clientId: string) => void;
}

/** VPN tab section for the built-in WireGuard and Outline clients. */
export function BuiltInVPNsSection({ status, onEditDomains }: Props) {
  const profiles = useProfiles();
  const helperReachable = useHelperReachable();
  const actions = useProfileActions();
  const picker = useWireGuardFilePicker();
  const [sheet, setSheet] = useState<ProfileSheet | null>(null);
  const [removing, setRemoving] = useState<ProfileInfo | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const list = profiles.data ?? [];
  const counts = useDomainCounts(list.map(profileClientId));
  // An unreachable helper is already said below; this is for it answering "no".
  const loadError = profiles.error && !profiles.error.isUnavailable ? helperFeatureErrorMessage(profiles.error) : null;
  const errors = [loadError, actions.actionError, localError].filter((e): e is string => Boolean(e));

  function replaceSecret(profile: ProfileInfo) {
    setLocalError(null);
    switch (profileKind(profile)) {
      case "outline":
        setSheet({ kind: "replaceOutlineKey", profile });
        break;
      case "wireguard":
        picker.open((file) => setSheet({ kind: "replaceWireGuardConfig", profile, file }));
        break;
      case "unknown":
        setLocalError("This profile type is not supported by this version of RouteWise.");
        break;
    }
  }

  return (
    <section className="grid grid-cols-[minmax(0,1fr)] gap-3" aria-labelledby="builtin-vpns-heading">
      <div>
        <h2 id="builtin-vpns-heading" className="text-sm font-semibold">
          Built-in VPNs
        </h2>
        <p className="text-xs text-muted-foreground">
          RouteWise runs these itself. Each carries only its own domain list; while one is off, its entries go direct.
        </p>
      </div>

      {list.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {profiles.data
            ? "No built-in VPNs yet. Import a WireGuard config or add an Outline key; RouteWise connects it itself and routes your domain list through it."
            : "Built-in VPNs appear here once the helper answers."}
        </p>
      ) : null}

      {list.map((profile) => {
        const clientId = profileClientId(profile);
        return (
          <BuiltInProfileCard
            key={profile.id}
            profile={profile}
            actions={actions}
            helperReachable={helperReachable}
            domainCount={counts[clientId]}
            routeCount={status?.tunnels?.find((t) => t.profileId === profile.id)?.routeCount}
            onRename={() => setSheet({ kind: "rename", profile })}
            onReplaceSecret={() => replaceSecret(profile)}
            onRemove={() => setRemoving(profile)}
            onEditDomains={onEditDomains ? () => onEditDomains(clientId) : undefined}
          />
        );
      })}

      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={!helperReachable}
          onClick={() => {
            setLocalError(null);
            picker.open((file) => setSheet({ kind: "importWireGuard", file }));
          }}>
          <FileDownIcon data-icon="inline-start" aria-hidden />
          Import WireGuard .conf…
        </Button>
        <Button variant="outline" size="sm" disabled={!helperReachable} onClick={() => setSheet({ kind: "addOutline" })}>
          <KeyRoundIcon data-icon="inline-start" aria-hidden />
          Add Outline Key…
        </Button>
      </div>
      {picker.input}

      {!helperReachable ? (
        <p className="text-xs text-orange-600 dark:text-orange-400">
          Unavailable until the app reconnects to the RouteWise helper.
        </p>
      ) : null}
      {errors.map((message) => (
        <p key={message} role="alert" className="text-xs text-destructive">
          {message}
        </p>
      ))}
      <p className="text-xs text-muted-foreground">
        Keys and configs are stored by the helper, readable by root only. RouteWise never shows them again.
      </p>

      <ProfileSheetHost sheet={sheet} onClose={() => setSheet(null)} actions={actions} />

      <AlertDialog open={removing !== null} onOpenChange={(open) => !open && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {removing?.name || removing?.id}?</AlertDialogTitle>
            <AlertDialogDescription>
              RouteWise disconnects it and deletes its stored key or config and its domain list. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (removing) void actions.remove(removing);
                setRemoving(null);
              }}>
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
