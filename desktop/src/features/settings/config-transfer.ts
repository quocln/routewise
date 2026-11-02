import type { Export as ConfigExport } from "@/lib/api/config.gen";

/** Why a chosen file cannot be a config export. */
export class TransferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransferError";
  }
}

/** `routewise-config-YYYYMMDD.json` in the user's local calendar day. */
export function defaultFileName(date: Date = new Date()): string {
  const pad = (n: number, width: number) => String(n).padStart(width, "0");
  return `routewise-config-${pad(date.getFullYear(), 4)}${pad(date.getMonth() + 1, 2)}${pad(date.getDate(), 2)}.json`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, v]) => [key, sortKeys(v)]),
    );
  }
  return value;
}

/** The document as human-readable JSON with sorted keys, ready to save. */
export function prettyPrint(document: unknown): string {
  return JSON.stringify(sortKeys(document), null, 2) + "\n";
}

/**
 * Parses a chosen file. The helper does the real validation; this only rejects
 * what cannot be a config object, so the error is immediate.
 */
export function parseConfigDocument(text: string): ConfigExport {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new TransferError("The file is not valid JSON.");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TransferError("The file is not a RouteWise config export.");
  }
  // The helper validates the document's fields and rejects what it does not accept.
  return value as ConfigExport;
}

/** What the save and open dialogs offer: JSON files. */
export const CONFIG_FILE_FILTER = { filterName: "JSON", extensions: ["json"] };
