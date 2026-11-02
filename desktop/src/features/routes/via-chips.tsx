import type { ListNames } from "@/features/activity/list-names";
import { cn } from "@/lib/utils";
import { routeLabel, vpnTitle, type Via } from "./route-model";

function Chip({ title, detail, selected, onClick }: { title: string; detail: string; selected: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onClick}
      className={cn(
        "flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs",
        selected ? "border-primary bg-primary/15" : "border-transparent bg-muted hover:bg-muted/70",
      )}>
      <span className="font-semibold">{title}</span>
      <span className="text-muted-foreground">{detail}</span>
    </button>
  );
}

interface Props {
  vias: readonly Via[];
  total: number;
  names: ListNames;
  selected: string | undefined;
  onSelect: (via: string | undefined) => void;
}

/** One chip per tunnel with its route count; choosing one shows only its routes. */
export function ViaChips({ vias, total, names, selected, onSelect }: Props) {
  return (
    <div className="flex gap-1.5 overflow-x-auto px-4 pb-2" data-testid="via-chips">
      <Chip title="All VPNs" detail={String(total)} selected={selected === undefined} onClick={() => onSelect(undefined)} />
      {vias.map((via) => (
        <Chip
          key={via.id}
          title={vpnTitle(names, via.clientId, via.name) ?? via.interface ?? "VPN"}
          detail={[via.interface, routeLabel(via.count)].filter(Boolean).join(" · ")}
          selected={selected === via.id}
          onClick={() => onSelect(selected === via.id ? undefined : via.id)}
        />
      ))}
    </div>
  );
}
