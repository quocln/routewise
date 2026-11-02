import { cn } from "@/lib/utils";
import type { DomainListItem, ListGroup } from "./domain-lists";
import { ListIconView, ListState } from "./list-visuals";

interface Props {
  items: readonly DomainListItem[];
  counts: Readonly<Record<string, number>>;
  selection: string;
  onSelect: (id: string) => void;
}

const GROUPS: { group: ListGroup; title?: string }[] = [
  { group: "any" },
  { group: "builtIn", title: "Built-in VPNs" },
  { group: "app", title: "VPN apps" },
];

/** The list of lists on the left of the Domains tab. */
export function DomainListSidebar({ items, counts, selection, onSelect }: Props) {
  return (
    <nav aria-label="Domain lists" className="flex h-full flex-col gap-3 overflow-y-auto p-2">
      {GROUPS.map(({ group, title }) => {
        const members = items.filter((item) => item.group === group);
        if (members.length === 0) return null;
        return (
          <section key={group} aria-label={title} className="flex flex-col gap-0.5">
            {title ? <h3 className="px-2 pb-1 text-xs font-medium text-muted-foreground">{title}</h3> : null}
            {members.map((item) => (
              <SidebarRow
                key={item.id}
                item={item}
                count={counts[item.id]}
                selected={item.id === selection}
                onSelect={onSelect}
              />
            ))}
          </section>
        );
      })}
    </nav>
  );
}

function SidebarRow({
  item,
  count,
  selected,
  onSelect,
}: {
  item: DomainListItem;
  count: number | undefined;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      aria-current={selected ? "true" : undefined}
      onClick={() => onSelect(item.id)}
      className={cn(
        "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm outline-none transition-colors focus-visible:ring-3 focus-visible:ring-ring/50",
        selected ? "bg-muted font-medium" : "hover:bg-muted/60",
      )}
    >
      <ListIconView icon={item.icon} />
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate">{item.title}</span>
        <ListState tone={item.stateTone} label={item.stateLabel} className="text-[0.7rem]" />
      </span>
      {count !== undefined ? (
        <span
          aria-label={`${count} ${count === 1 ? "entry" : "entries"}`}
          className="rounded-full bg-muted-foreground/15 px-1.5 text-xs text-muted-foreground tabular-nums"
        >
          {count}
        </span>
      ) : null}
    </button>
  );
}
