"use client";

import { EllipsisIcon, KeyRoundIcon, NetworkIcon, ShieldIcon, SendIcon } from "lucide-react";
import type { ProfileInfo } from "@/lib/api/types.gen";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import type { ProfileActions } from "./use-profile-actions";
import {
  displayName,
  isRunning,
  kindTitle,
  profileKind,
  profileState,
  stateText,
  statsLine,
  type ProfileKind,
  type ProfileState,
} from "./vpn-format";

const DOT: Record<ProfileState, string> = {
  connected: "bg-emerald-500",
  connecting: "bg-amber-500",
  error: "bg-destructive",
  needsCredentials: "bg-orange-500",
  disconnected: "bg-muted-foreground",
  unknown: "bg-muted-foreground",
};

const KIND_ICON: Record<ProfileKind, typeof ShieldIcon> = {
  wireguard: ShieldIcon,
  outline: SendIcon,
  socks5: NetworkIcon,
  http: NetworkIcon,
  unknown: NetworkIcon,
};

function domainSummary(count: number | undefined): string {
  if (count === undefined) return "Counting…";
  if (count === 0) return "No entries yet — nothing goes through it";
  return count === 1 ? "1 entry goes through this VPN" : `${count} entries go through this VPN`;
}

interface Props {
  profile: ProfileInfo;
  actions: Pick<ProfileActions, "pendingConnect" | "pendingAutoConnect" | "busy" | "setConnected" | "setAutoConnect">;
  helperReachable: boolean;
  /** Entries in this VPN's domain list; undefined until counted. */
  domainCount: number | undefined;
  /** Routes the helper holds through this VPN; undefined while it is not up. */
  routeCount: number | undefined;
  onRename: () => void;
  onReplaceSecret: () => void;
  onRemove: () => void;
  /** Absent when the window cannot jump to the Domains tab. */
  onEditDomains?: () => void;
}

/** One built-in VPN as a card: what it is and whether it is up, one Connect or Disconnect button, then its details. */
export function BuiltInProfileCard({
  profile,
  actions,
  helperReachable,
  domainCount,
  routeCount,
  onRename,
  onReplaceSecret,
  onRemove,
  onEditDomains,
}: Props) {
  const kind = profileKind(profile);
  const secretNoun = kind === "socks5" || kind === "http" ? "Proxy" : "Key/Config";
  const state = profileState(profile);
  const title = displayName(profile.name, profile.id);
  const isBusy = actions.busy.has(profile.id);
  const isSwitching = actions.pendingConnect[profile.id] !== undefined;
  const needsCredentials = state === "needsCredentials";
  const autoConnect = actions.pendingAutoConnect[profile.id] ?? profile.autoConnect;
  const locked = !helperReachable || isBusy;
  const Icon = KIND_ICON[kind];

  return (
    <Card size="sm" data-testid={`profile-${profile.id}`}>
      <CardContent className="grid grid-cols-[minmax(0,1fr)] gap-3">
        <div className="flex items-center gap-3">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Icon className="size-5" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{title}</p>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Badge variant="secondary">{kindTitle(kind)}</Badge>
              <span className={cn("size-1.5 shrink-0 rounded-full", DOT[state])} aria-hidden />
              <span data-testid="profile-state">{stateText(profile, routeCount)}</span>
            </div>
          </div>
          {isSwitching || isBusy ? (
            <span className="text-xs text-muted-foreground" role="status">
              {isBusy ? "Working…" : actions.pendingConnect[profile.id] ? "Connecting…" : "Disconnecting…"}
            </span>
          ) : null}
          {needsCredentials ? (
            <Button variant="outline" size="sm" disabled={locked} onClick={onReplaceSecret}>
              Add {secretNoun}…
            </Button>
          ) : isRunning(state) ? (
            <Button
              variant="outline"
              size="sm"
              disabled={locked || isSwitching}
              onClick={() => void actions.setConnected(profile, false)}>
              Disconnect
            </Button>
          ) : (
            <Button size="sm" disabled={locked || isSwitching} onClick={() => void actions.setConnected(profile, true)}>
              Connect
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger
              disabled={locked}
              aria-label={`More actions for ${title}`}
              render={<Button variant="ghost" size="icon-sm" />}>
              <EllipsisIcon aria-hidden />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {onEditDomains ? <DropdownMenuItem onClick={onEditDomains}>Edit Domains…</DropdownMenuItem> : null}
              <DropdownMenuItem onClick={onRename}>Rename…</DropdownMenuItem>
              <DropdownMenuItem onClick={onReplaceSecret}>
                {needsCredentials ? `Add ${secretNoun}…` : `Replace ${secretNoun}…`}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={onRemove}>
                Remove…
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {state === "error" && profile.error ? (
          <p role="alert" className="rounded-md bg-destructive/10 p-2 text-xs text-destructive">
            {profile.error}
          </p>
        ) : null}

        <dl className="grid grid-cols-[4.5rem_1fr] items-baseline gap-x-3 gap-y-2 text-sm">
          {profile.server ? (
            <>
              <dt className="text-right text-muted-foreground">Server</dt>
              <dd className="truncate font-mono text-xs" title={profile.server}>
                {profile.server}
              </dd>
            </>
          ) : null}
          {state === "connected" && profile.stats ? (
            <>
              <dt className="text-right text-muted-foreground">Traffic</dt>
              <dd className="text-muted-foreground">{statsLine(profile.stats, kind)}</dd>
            </>
          ) : null}
          <dt className="text-right text-muted-foreground">Domains</dt>
          <dd className="flex items-center gap-2">
            <span className={cn(domainCount === 0 && "text-orange-600 dark:text-orange-400")}>
              {domainSummary(domainCount)}
            </span>
            {onEditDomains ? (
              <Button variant="outline" size="xs" onClick={onEditDomains}>
                Edit Domains…
              </Button>
            ) : null}
          </dd>
          {needsCredentials ? (
            <>
              <dt className="text-right text-muted-foreground">Key</dt>
              <dd className="flex items-center gap-1.5 text-orange-600 dark:text-orange-400">
                <KeyRoundIcon className="size-3.5" aria-hidden />
                No key or config yet — add one to connect.
              </dd>
            </>
          ) : (
            <>
              <dt className="text-right text-muted-foreground">Startup</dt>
              <dd>
                <Label className="font-normal">
                  <Checkbox
                    checked={autoConnect}
                    disabled={locked}
                    onCheckedChange={(checked) => void actions.setAutoConnect(profile, checked)}
                  />
                  Connect automatically when RouteWise starts
                </Label>
              </dd>
            </>
          )}
        </dl>
      </CardContent>
    </Card>
  );
}
