import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";
import { ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger } from "@/components/ui/context-menu";
import { DomainEntryRow } from "./domain-entry-row";

const ROW_HEIGHT = 32;

export interface EntryListProps {
  rows: readonly string[];
  selected: ReadonlySet<string>;
  canEdit: boolean;
  /** The filter text when it matched nothing. */
  noMatch: string | undefined;
  onClickRow: (pattern: string, event: React.MouseEvent) => void;
  /** The context menu opened on a row: one outside the selection becomes the selection. */
  onContextRow: (pattern: string) => void;
  onRemove: (patterns: ReadonlySet<string>) => void;
  onCopy: (patterns: readonly string[]) => void;
  onSelectAll: () => void;
}

/**
 * The entries in a virtualised, multi-select list; Delete removes the selection, Cmd+C copies it.
 * The context menu acts on the selection when the row is in it, else on the row alone.
 */
export function EntryList({
  rows,
  selected,
  canEdit,
  noMatch,
  onClickRow,
  onContextRow,
  onRemove,
  onCopy,
  onSelectAll,
}: EntryListProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  // The virtualizer is not memoised by the React Compiler, which is fine: it is read only here.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  function onKeyDown(event: React.KeyboardEvent) {
    const modifier = event.metaKey || event.ctrlKey;
    if ((event.key === "Delete" || event.key === "Backspace") && selected.size > 0) {
      event.preventDefault();
      onRemove(selected);
    } else if (modifier && event.key.toLowerCase() === "c" && selected.size > 0) {
      event.preventDefault();
      onCopy([...selected].sort());
    } else if (modifier && event.key.toLowerCase() === "a") {
      event.preventDefault();
      onSelectAll();
    }
  }

  return (
    <div className="relative min-h-0 flex-1 rounded-lg border">
      <div
        ref={scrollRef}
        role="listbox"
        aria-label="Entries"
        aria-multiselectable="true"
        tabIndex={0}
        onKeyDown={onKeyDown}
        className="h-full overflow-auto outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((row) => {
            const pattern = rows[row.index];
            const picked: ReadonlySet<string> = selected.has(pattern) ? selected : new Set([pattern]);
            return (
              <ContextMenu key={pattern}>
                <ContextMenuTrigger
                  className="absolute inset-x-0"
                  style={{ height: row.size, transform: `translateY(${row.start}px)` }}
                >
                  <DomainEntryRow
                    pattern={pattern}
                    selected={selected.has(pattern)}
                    canRemove={canEdit}
                    onClick={(event) => onClickRow(pattern, event)}
                    onContextMenu={() => onContextRow(pattern)}
                    onRemove={() => onRemove(new Set([pattern]))}
                  />
                </ContextMenuTrigger>
                <ContextMenuContent>
                  <ContextMenuItem onClick={() => onCopy([...picked].sort())}>Copy</ContextMenuItem>
                  <ContextMenuItem variant="destructive" disabled={!canEdit} onClick={() => onRemove(picked)}>
                    {picked.size > 1 ? `Remove ${picked.size} Entries` : "Remove"}
                  </ContextMenuItem>
                </ContextMenuContent>
              </ContextMenu>
            );
          })}
        </div>
      </div>
      {noMatch !== undefined ? (
        <p className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
          No entries match &quot;{noMatch}&quot;
        </p>
      ) : null}
    </div>
  );
}
