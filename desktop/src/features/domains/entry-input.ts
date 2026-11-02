import { canonicalEntry, validateEntry } from "./list-entry-validator";

/**
 * Splits what was typed or pasted into the add field: entries may be separated
 * by new lines, commas, semicolons, or spaces.
 */
export function parseEntryInput(text: string): string[] {
  return text.split(/[,;\s]+/).filter((entry) => entry !== "");
}

/**
 * Parses the bulk editor's text into entries: one non-empty, non-comment line
 * per entry. Its count and its save both use this, so they agree on what an
 * entry is.
 */
export function parseDomainLines(text: string): string[] {
  return text
    .split(/\r\n|\n|\r/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

/** The first malformed entry with its reason, or undefined when all are valid. */
export function firstInvalidEntry(entries: readonly string[]): string | undefined {
  for (const entry of entries) {
    const message = validateEntry(entry);
    if (message) return `${entry}: ${message}`;
  }
  return undefined;
}

export type AddPlan =
  | { kind: "nothing" }
  | { kind: "invalid"; message: string }
  | { kind: "duplicates" }
  | { kind: "add"; fresh: string[]; skipped: number };

/**
 * Decides what adding `input` to a list holding `existing` does. When any
 * entry is malformed nothing is added and the reason is returned, so the user
 * can fix what they typed. Entries already present (compared in canonical
 * form, so 10.20.5.1/16 duplicates 10.20.0.0/16) are skipped.
 */
export function planAdd(input: string, existing: readonly string[]): AddPlan {
  const candidates = parseEntryInput(input);
  if (candidates.length === 0) return { kind: "nothing" };

  const seen = new Set(existing.map(canonicalEntry));
  const fresh: string[] = [];
  for (const entry of candidates) {
    const message = validateEntry(entry);
    if (message) return { kind: "invalid", message: `${entry}: ${message}` };
    const canonical = canonicalEntry(entry);
    if (!seen.has(canonical)) {
      seen.add(canonical);
      fresh.push(entry);
    }
  }
  if (fresh.length === 0) return { kind: "duplicates" };
  return { kind: "add", fresh, skipped: candidates.length - fresh.length };
}
