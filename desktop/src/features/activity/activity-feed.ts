import type { Event as ActivityEvent } from "@/lib/api/activity.gen";
import type { AccessListResult, ActivityResult } from "@/lib/api/types.gen";
import type { Entry as AccessEntry } from "@/lib/api/history.gen";

/** The most events the view keeps; older ones fall off the end. */
export const MAX_KEPT_EVENTS = 2000;
/** The most connections the view keeps, newest first. */
export const MAX_KEPT_ENTRIES = 2000;
/** Rows per access.list request: the first page and each "Load older" page. */
export const ACCESS_PAGE_SIZE = 500;

/**
 * Folds a poll result into the events on screen, newest first. The first
 * result after a (re)start replaces them; later ones add only events not seen.
 * Events at or below `floor` were cleared by the user and stay hidden.
 */
export function mergeActivity(
  current: ActivityEvent[],
  result: ActivityResult,
  initial: boolean,
  floor = 0,
): ActivityEvent[] {
  const incoming = result.events.filter((e) => e.seq > floor).sort((a, b) => b.seq - a.seq);
  if (initial) return incoming.slice(0, MAX_KEPT_EVENTS);
  const newest = current[0]?.seq ?? 0;
  const fresh = incoming.filter((e) => e.seq > newest);
  return fresh.length === 0 ? current : [...fresh, ...current].slice(0, MAX_KEPT_EVENTS);
}

/**
 * Folds an access.list result into the connections on screen, newest first.
 * The first result replaces them; later ones (oldest first) are prepended.
 */
export function mergeAccess(current: AccessEntry[], result: AccessListResult, initial: boolean): AccessEntry[] {
  const incoming = [...(result.entries ?? [])].sort((a, b) => b.id - a.id);
  if (initial) return incoming.slice(0, MAX_KEPT_ENTRIES);
  const newest = current[0]?.id ?? 0;
  const fresh = incoming.filter((e) => e.id > newest);
  return fresh.length === 0 ? current : [...fresh, ...current].slice(0, MAX_KEPT_ENTRIES);
}

/**
 * Appends an older page. The helper's `untilMs` is inclusive and has
 * millisecond resolution, so rows at or after the oldest id come back too.
 */
export function appendOlder(current: AccessEntry[], page: AccessEntry[]): AccessEntry[] {
  const oldest = current[current.length - 1]?.id ?? Infinity;
  const older = page.filter((e) => e.id < oldest).sort((a, b) => b.id - a.id);
  return [...current, ...older].slice(0, MAX_KEPT_ENTRIES);
}
