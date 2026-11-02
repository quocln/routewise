"use client";

import { useState } from "react";
import { Skeleton } from "@/components/ui/skeleton";
import { usePersistedState } from "@/lib/use-persisted-state";
import { DomainBulkEditDialog } from "./domain-bulk-edit-dialog";
import { DomainEntriesPane } from "./domain-entries-pane";
import { DomainListSidebar } from "./domain-list-sidebar";
import { ANY_VPN_ID, listCaption } from "./domain-lists";
import { useDomainListEntries } from "./use-domain-list-entries";
import { useDomainLists } from "./use-domain-lists";

const isString = (value: unknown): value is string => typeof value === "string";

interface Props {
  /** Switches to the VPN tab; without it the "Open in VPN Tab" action is hidden. */
  onOpenVpnTab?: () => void;
}

/**
 * The Domains tab: every list on the left (Any VPN, each built-in VPN, each
 * VPN app) and the chosen list's entries on the right.
 */
export function DomainsTab({ onOpenVpnTab }: Props) {
  const lists = useDomainLists();
  const [storedSelection, setStoredSelection] = usePersistedState("domains.selectedList", ANY_VPN_ID, isString);

  if (!lists.isReady) {
    return (
      <div className="flex h-full gap-2 p-4" aria-busy="true">
        <Skeleton className="h-full w-48" />
        <Skeleton className="h-full flex-1" />
      </div>
    );
  }

  // The shown VPN was removed: its list is gone, so Any VPN stands in without forgetting the choice.
  const item = lists.items.find((i) => i.id === storedSelection) ?? lists.items[0];

  return (
    <div className="flex h-full min-h-0">
      <div className="w-52 shrink-0 border-r">
        <DomainListSidebar items={lists.items} counts={lists.counts} selection={item.id} onSelect={setStoredSelection} />
      </div>
      <div className="min-w-0 flex-1">
        <SelectedList
          key={item.id}
          item={item}
          caption={listCaption(item, lists.status)}
          isHelperConnected={lists.isHelperConnected}
          onOpenVpnTab={onOpenVpnTab}
        />
      </div>
    </div>
  );
}

interface SelectedListProps {
  item: ReturnType<typeof useDomainLists>["items"][number];
  caption: string;
  isHelperConnected: boolean;
  onOpenVpnTab?: () => void;
}

/** The entries of one list with its bulk editor and error line; remounts per list. */
function SelectedList({ item, caption, isHelperConnected, onOpenVpnTab }: SelectedListProps) {
  const list = useDomainListEntries(item.id);
  const [isBulkEditing, setIsBulkEditing] = useState(false);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="min-h-0 flex-1">
        <DomainEntriesPane
          item={item}
          caption={caption}
          list={list}
          isHelperConnected={isHelperConnected}
          onEditAsText={() => setIsBulkEditing(true)}
          onOpenVpnTab={onOpenVpnTab}
        />
      </div>
      {list.error ? (
        <p role="alert" className="px-4 pb-3 text-xs text-destructive">
          {list.error}
        </p>
      ) : null}
      <DomainBulkEditDialog
        open={isBulkEditing}
        onOpenChange={setIsBulkEditing}
        title={`Edit ${item.title} as text`}
        entries={list.entries}
        onSave={list.setEntries}
      />
    </div>
  );
}
