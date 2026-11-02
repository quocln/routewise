/** Wire keys of the app's preferences, as the helper stores them. */
export const PREF_KEYS = {
  launchAtLogin: "launchAtLogin",
  keepWindowOnTop: "keepWindowOnTop",
  lastUpdateCheck: "lastUpdateCheck",
} as const;

export interface Preferences {
  launchAtLogin: boolean;
  keepWindowOnTop: boolean;
  /** When updates were last checked; null when never. */
  lastUpdateCheck: Date | null;
}

export const DEFAULT_PREFERENCES: Preferences = {
  launchAtLogin: false,
  keepWindowOnTop: true,
  lastUpdateCheck: null,
};

function toDate(value: unknown): Date | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms);
}

/** Reads prefs.get's answer. A missing or mistyped value is the default, never a stale one. */
export function parsePreferences(prefs: Record<string, unknown> | undefined): Preferences {
  const launch = prefs?.[PREF_KEYS.launchAtLogin];
  const onTop = prefs?.[PREF_KEYS.keepWindowOnTop];
  return {
    launchAtLogin: typeof launch === "boolean" ? launch : DEFAULT_PREFERENCES.launchAtLogin,
    keepWindowOnTop: typeof onTop === "boolean" ? onTop : DEFAULT_PREFERENCES.keepWindowOnTop,
    lastUpdateCheck: toDate(prefs?.[PREF_KEYS.lastUpdateCheck]),
  };
}
