import { useCallback, useMemo, useSyncExternalStore } from "react";

/** Prefix that keeps the app's keys apart from anything else in the webview. */
const KEY_PREFIX = "routewise.";

/** Values written this session; they win when storage refuses a write. */
const written = new Map<string, string>();
const listeners = new Set<() => void>();

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function readRaw(key: string): string | null {
  const own = written.get(key);
  if (own !== undefined) return own;
  try {
    return window.localStorage.getItem(KEY_PREFIX + key);
  } catch {
    return null;
  }
}

function parse<T>(raw: string | null, isValid: (value: unknown) => value is T): T | undefined {
  if (raw === null) return undefined;
  try {
    const value: unknown = JSON.parse(raw);
    return isValid(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** Reads a stored value; storage that is missing, blocked, or corrupt reads as absent. */
export function readStored<T>(key: string, isValid: (value: unknown) => value is T): T | undefined {
  return parse(readRaw(key), isValid);
}

/** Stores a value; a failed write only loses it across windows, not in this one. */
export function writeStored(key: string, value: unknown): void {
  const raw = JSON.stringify(value);
  written.set(key, raw);
  try {
    window.localStorage.setItem(KEY_PREFIX + key, raw);
  } catch {
    // Private mode or a full quota: keep the in-memory value only.
  }
  listeners.forEach((listener) => listener());
}

/** Forgets this session's values; tests use it to start from storage alone. */
export function resetWrittenForTests(): void {
  written.clear();
}

/**
 * State that survives the window being destroyed on close (the tray keeps no
 * webview). Only small UI choices belong here, never helper data or secrets.
 * The static export is prerendered without storage, so the server snapshot is
 * the fallback and the stored value takes over after hydration.
 */
export function usePersistedState<T>(
  key: string,
  fallback: T,
  isValid: (value: unknown) => value is T,
): [T, (value: T) => void] {
  const raw = useSyncExternalStore(
    subscribe,
    () => readRaw(key),
    () => null,
  );
  const value = useMemo(() => parse(raw, isValid) ?? fallback, [raw, isValid, fallback]);
  const update = useCallback((next: T) => writeStored(key, next), [key]);
  return [value, update];
}
