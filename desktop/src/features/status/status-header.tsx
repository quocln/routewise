"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useStatus } from "@/lib/rpc/queries";
import { presentStatus, type StatusTone } from "./status-presentation";

const DOT: Record<StatusTone, string> = {
  ok: "bg-emerald-500",
  idle: "bg-muted-foreground",
  warning: "bg-amber-500",
  error: "bg-destructive",
};

/** Live helper status: connection state, tunnels and route count. */
export function StatusHeader() {
  const { data, error } = useStatus();
  const view = presentStatus(data, error);

  return (
    <header className="flex items-center gap-3 border-b px-4 py-3" aria-live="polite">
      <span className={cn("size-2.5 shrink-0 rounded-full", DOT[view.tone])} aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium" data-testid="status-label">
          {view.label}
        </p>
        <p className="truncate text-xs text-muted-foreground" data-testid="status-detail">
          {view.detail}
        </p>
      </div>
      {data?.captureDropped ? <Badge variant="destructive">Capture dropping packets</Badge> : null}
      {data?.wildcardError ? <Badge variant="secondary">Wildcard routing off</Badge> : null}
    </header>
  );
}
