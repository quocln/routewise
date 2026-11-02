import {
  Ban,
  CircleHelp,
  CircleMinus,
  CirclePlus,
  Globe,
  Info,
  Network,
  ShieldCheck,
  TriangleAlert,
  AppWindow,
  type LucideIcon,
} from "lucide-react";
import { memo } from "react";
import { cn } from "@/lib/utils";
import type { ActivityRow, RowRoute } from "./activity-row";
import type { ListGroup } from "./list-names";

const KIND_ICONS: Record<string, { icon: LucideIcon; className: string }> = {
  vpn: { icon: Network, className: "text-blue-500" },
  route_added: { icon: CirclePlus, className: "text-green-500" },
  route_removed: { icon: CircleMinus, className: "text-orange-500" },
  refused: { icon: Ban, className: "text-red-500" },
  dns: { icon: Globe, className: "text-muted-foreground" },
};
const UNKNOWN_KIND = { icon: CircleHelp, className: "text-muted-foreground" };

const GROUP_ICONS: Record<ListGroup, LucideIcon> = { any: Globe, builtIn: ShieldCheck, app: AppWindow };

function RouteLabel({ route }: { route: RowRoute }) {
  const text =
    route.kind === "vpn" ? `via ${route.client || "VPN"}` : route.kind === "direct" ? "Direct" : "Other";
  const color = route.kind === "vpn" ? "text-green-600" : route.kind === "direct" ? "text-muted-foreground" : "text-orange-500";
  return <span className={cn("shrink-0 text-xs font-medium whitespace-nowrap", color)}>{`→ ${text}`}</span>;
}

interface MatchedEntryProps {
  title?: string;
  group?: ListGroup;
  rule?: string;
  /** Shown when nothing matched. */
  placeholder?: string;
}

/** The list a name or route matched, with the entry that matched; `placeholder` when none did. */
export function MatchedEntry({ title, group, rule, placeholder = "\u2014" }: MatchedEntryProps) {
  if (title === undefined || group === undefined) {
    return <span className="truncate text-xs text-muted-foreground">{placeholder}</span>;
  }
  const Icon = GROUP_ICONS[group];
  return (
    <span className="inline-flex min-w-0 items-center gap-1 text-xs text-primary">
      <Icon className="size-3 shrink-0" aria-hidden />
      <span className="shrink-0 font-medium">{title}</span>
      {rule ? <span className="truncate font-mono text-foreground">{rule}</span> : null}
    </span>
  );
}

/**
 * One row of the Activity tab, the same in every mode: time, name and address
 * on the first line; the matched list entry and where the traffic went on the second.
 */
export const ActivityRowView = memo(function ActivityRowView({ row }: { row: ActivityRow }) {
  const kind = row.kind === undefined ? undefined : (KIND_ICONS[row.kind] ?? UNKNOWN_KIND);
  return (
    <div className="flex h-full items-start gap-2 py-1.5" data-testid="activity-row">
      <span className="w-28 shrink-0 pt-0.5 font-mono text-xs text-muted-foreground">{row.time}</span>
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <div className="flex min-w-0 items-center gap-2">
          {kind ? <kind.icon className={cn("size-4 shrink-0", kind.className)} aria-hidden /> : null}
          <span className="truncate text-sm font-medium">{row.title}</span>
          {row.endpoint ? (
            <span className="shrink-0 font-mono text-xs text-muted-foreground">{row.endpoint}</span>
          ) : null}
          {row.proto ? <span className="shrink-0 text-xs text-muted-foreground">{row.proto}</span> : null}
        </div>
        <div className="flex min-w-0 items-center gap-2">
          <div className="flex min-w-0 flex-1 items-center gap-2 truncate">
            <MatchedEntry title={row.listTitle} group={row.listGroup} rule={row.rule} />
            {row.detail ? <span className="truncate text-xs text-muted-foreground">{row.detail}</span> : null}
          </div>
          {row.warning ? (
            <span
              className="inline-flex shrink-0 items-center gap-1 text-xs text-orange-500"
              title={row.warning}
              data-testid="row-warning">
              <TriangleAlert className="size-3" aria-hidden />
              {row.warningLabel}
            </span>
          ) : row.notice ? (
            <span
              className="inline-flex shrink-0 items-center gap-1 text-xs text-muted-foreground"
              title={row.notice}
              data-testid="row-notice">
              <Info className="size-3" aria-hidden />
              {row.noticeLabel}
            </span>
          ) : null}
          {row.route ? <RouteLabel route={row.route} /> : null}
        </div>
      </div>
    </div>
  );
});
