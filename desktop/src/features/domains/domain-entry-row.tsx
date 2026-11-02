import { Asterisk, CircleMinus, Globe, Grid3x3, Hash, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { entryDisplayKind } from "./list-entry-validator";

const KINDS: Record<ReturnType<typeof entryDisplayKind>, { icon: LucideIcon; label: string }> = {
  ip: { icon: Hash, label: "IP" },
  range: { icon: Grid3x3, label: "Range" },
  wildcard: { icon: Asterisk, label: "Wildcard" },
  domain: { icon: Globe, label: "Domain" },
};

interface Props {
  pattern: string;
  selected: boolean;
  canRemove: boolean;
  onClick: (event: React.MouseEvent) => void;
  onContextMenu: () => void;
  onRemove: () => void;
}

/** One entry: what kind it is, the pattern, and a remove button. */
export function DomainEntryRow({ pattern, selected, canRemove, onClick, onContextMenu, onRemove }: Props) {
  const { icon: Icon, label } = KINDS[entryDisplayKind(pattern)];
  return (
    <div
      role="option"
      aria-selected={selected}
      onClick={onClick}
      onContextMenu={onContextMenu}
      className={cn(
        "group flex h-full items-center gap-2 border-b px-2 text-sm select-none",
        selected ? "bg-primary/10" : "hover:bg-muted/50",
      )}
    >
      <Icon aria-hidden className="size-4 shrink-0 text-muted-foreground" />
      <span className="min-w-0 flex-1 truncate font-mono select-text" title={pattern}>
        {pattern}
      </span>
      <span className="text-xs text-muted-foreground">{label}</span>
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label={`Remove ${pattern}`}
        title={`Remove ${pattern}`}
        disabled={!canRemove}
        className="opacity-40 hover:text-destructive group-hover:opacity-100 focus-visible:opacity-100"
        onClick={(event) => {
          event.stopPropagation();
          onRemove();
        }}
      >
        <CircleMinus />
      </Button>
    </div>
  );
}
