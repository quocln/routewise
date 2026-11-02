"use client";

import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";
import { ActivityRowView } from "./activity-row-view";
import type { ActivityRow } from "./activity-row";

const ROW_HEIGHT = 52;

/** The rows in a virtualised list: only the ones in view are in the DOM. */
export function ActivityList({ rows }: { rows: ActivityRow[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  // The virtualizer is not memoised by the React Compiler, which is fine: it is read only here.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 10,
    getItemKey: (index) => rows[index].id,
  });
  return (
    <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto" data-testid="activity-scroll">
      <ul className="relative" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((item) => (
          <li
            key={item.key}
            className="absolute inset-x-0 border-b px-4"
            style={{ height: item.size, transform: `translateY(${item.start}px)` }}>
            <ActivityRowView row={rows[item.index]} />
          </li>
        ))}
      </ul>
    </div>
  );
}
