import { Ellipsis, Inbox, LoaderCircle, Search, Trash2, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { DomainAddBar, type AddFeedback } from "./domain-add-bar";
import { EntryList } from "./domain-entry-list";
import type { DomainListItem } from "./domain-lists";
import { EMPTY_SELECTION, selectionAfterClick, type SelectionState } from "./entry-selection";
import { ListIconView, ListState } from "./list-visuals";
import type { DomainListEntries } from "./use-domain-list-entries";

/** The filter field appears once a list is long enough to need it. */
const FILTER_THRESHOLD = 8;

interface Props {
  item: DomainListItem;
  caption: string;
  list: DomainListEntries;
  isHelperConnected: boolean;
  onEditAsText: () => void;
  /** Absent when the host cannot switch tabs; the menu item is then hidden. */
  onOpenVpnTab?: () => void;
}

async function copyToClipboard(patterns: readonly string[]) {
  try {
    await navigator.clipboard.writeText(patterns.join("\n"));
    toast.success(patterns.length === 1 ? "Copied 1 entry" : `Copied ${patterns.length} entries`);
  } catch {
    toast.error("Could not copy to the clipboard");
  }
}

/**
 * The right side of the Domains tab: the selected list's entries, an add
 * field, search, and removal. Every change is sent to the helper at once. Mount
 * it with the list's id as `key` so a new list starts with fresh field state.
 */
export function DomainEntriesPane({ item, caption, list, isHelperConnected, onEditAsText, onOpenVpnTab }: Props) {
  const { entries, isLoading, isSaving } = list;
  const [addFeedback, setAddFeedback] = useState<AddFeedback>();
  const [search, setSearch] = useState("");
  const [selection, setSelection] = useState<SelectionState>(EMPTY_SELECTION);

  const query = search.trim().toLowerCase();
  const filtered = useMemo(
    () => (query === "" ? entries : entries.filter((p) => p.toLowerCase().includes(query))),
    [entries, query],
  );
  // An entry removed elsewhere drops out of the selection.
  const selected = useMemo(() => {
    const present = new Set(entries);
    return new Set([...selection.selected].filter((p) => present.has(p)));
  }, [entries, selection.selected]);

  const canEdit = isHelperConnected && !isSaving && !isLoading;

  async function remove(patterns: ReadonlySet<string>) {
    if (!canEdit || patterns.size === 0) return;
    if (await list.removeEntries(patterns)) {
      setSelection((s) => ({ ...s, selected: new Set([...s.selected].filter((p) => !patterns.has(p))) }));
      setAddFeedback(undefined);
    }
  }

  const total = entries.length;
  const noun = total === 1 ? "entry" : "entries";
  const countLabel = query === "" ? `${total} ${noun}` : `${filtered.length} of ${total} ${noun}`;

  return (
    <div className="flex h-full min-w-0 flex-col gap-2.5 p-4">
      <header className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <ListIconView icon={item.icon} className="size-5" />
          <h2 className="truncate text-base font-semibold">{item.title}</h2>
          <ListState tone={item.stateTone} label={item.stateLabel} className="text-xs" />
          <div className="ml-auto flex items-center gap-1">
            {isSaving || isLoading ? (
              <LoaderCircle aria-label="Working" className="size-4 animate-spin text-muted-foreground" />
            ) : null}
            <DropdownMenu>
              <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label="List actions" />}>
                <Ellipsis />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem disabled={!canEdit} onClick={onEditAsText}>
                  Edit as Text…
                </DropdownMenuItem>
                <DropdownMenuItem disabled={total === 0} onClick={() => void copyToClipboard(entries)}>
                  Copy All Entries
                </DropdownMenuItem>
                {item.group !== "any" && onOpenVpnTab ? (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={onOpenVpnTab}>Open in VPN Tab</DropdownMenuItem>
                  </>
                ) : null}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">{caption}</p>
      </header>

      <DomainAddBar canEdit={canEdit} feedback={addFeedback} onFeedback={setAddFeedback} onAdd={list.addEntries} />

      {total > FILTER_THRESHOLD ? (
        <div className="relative">
          <Search aria-hidden className="absolute top-2 left-2 size-4 text-muted-foreground" />
          <Input
            aria-label="Filter entries"
            placeholder="Filter"
            value={search}
            className="px-8"
            onChange={(event) => setSearch(event.target.value)}
          />
          {search !== "" ? (
            <Button
              variant="ghost"
              size="icon-xs"
              aria-label="Clear filter"
              className="absolute top-1 right-1"
              onClick={() => setSearch("")}
            >
              <X />
            </Button>
          ) : null}
        </div>
      ) : null}

      {total === 0 && !isLoading ? (
        <EmptyState item={item} />
      ) : (
        <EntryList
          rows={filtered}
          selected={selected}
          canEdit={canEdit}
          noMatch={filtered.length === 0 && query !== "" ? search : undefined}
          onClickRow={(pattern, event) =>
            setSelection((s) =>
              selectionAfterClick(s, filtered, pattern, {
                toggle: event.metaKey || event.ctrlKey,
                range: event.shiftKey,
              }),
            )
          }
          onContextRow={(pattern) =>
            setSelection((s) => (s.selected.has(pattern) ? s : { selected: new Set([pattern]), anchor: pattern }))
          }
          onRemove={(patterns) => void remove(patterns)}
          onCopy={(patterns) => void copyToClipboard(patterns)}
          onSelectAll={() => setSelection({ selected: new Set(filtered), anchor: undefined })}
        />
      )}

      <footer className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>{countLabel}</span>
        {selected.size > 0 ? (
          <span className="ml-auto flex items-center gap-1">
            <Button size="xs" variant="outline" onClick={() => void copyToClipboard([...selected].sort())}>
              Copy {selected.size}
            </Button>
            <Button size="xs" variant="destructive" disabled={!canEdit} onClick={() => void remove(selected)}>
              <Trash2 data-icon="inline-start" />
              Remove {selected.size} Selected
            </Button>
          </span>
        ) : null}
      </footer>
    </div>
  );
}

function EmptyState({ item }: { item: DomainListItem }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-lg border border-dashed text-center">
      <Inbox aria-hidden className="size-8 text-muted-foreground" />
      <p className="font-medium">No entries</p>
      <p className="text-xs text-muted-foreground">
        {item.group === "any"
          ? "Add a domain or IP above to send it through your VPN app."
          : `Add a domain or IP above to send it through ${item.title}.`}
      </p>
    </div>
  );
}
