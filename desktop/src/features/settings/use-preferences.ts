import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { rpc } from "@/lib/rpc/rpc-client";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import { launchAtLoginGet, launchAtLoginSet, windowSetKeepOnTop } from "@/lib/native/native-commands";
import { NativeError } from "@/lib/native/native-error";
import { DEFAULT_PREFERENCES, PREF_KEYS, parsePreferences, type Preferences } from "./preferences";

export const PREFS_KEY = ["prefs.get"] as const;
const LOGIN_ITEM_KEY = ["native", "launch-at-login"] as const;

type BoolPref = "launchAtLogin" | "keepWindowOnTop";

export interface PreferencesState {
  prefs: Preferences;
  /** True once the helper has answered; until then the defaults show. */
  isLoaded: boolean;
  /** Whether the system holds a login item for the app; undefined until known or when it cannot be read. */
  loginItemEnabled: boolean | undefined;
  /** Why the last change was refused, until the next change. */
  errorMessage: string | null;
  setBool: (key: BoolPref, value: boolean) => void;
}

const writePref = (key: BoolPref, value: boolean) => rpc("prefs.set", { key: PREF_KEYS[key], value });

/** Puts a preference back after a change that could not be completed; the original failure is what the user sees. */
async function restore(undo: () => Promise<unknown>): Promise<void> {
  try {
    await undo();
  } catch {
    // Nothing more to do: the next load shows what is stored.
  }
}

/**
 * Makes a preference true in the app and in the OS. The login item is the
 * truth, so it changes first and the stored preference follows; when the
 * preference cannot be saved the login item goes back. The window level follows
 * the stored preference, so it is saved first and the window changes after;
 * when the window cannot change the preference goes back.
 */
async function applyBool(key: BoolPref, value: boolean, previous: boolean): Promise<void> {
  if (key === "launchAtLogin") {
    try {
      await launchAtLoginSet(value);
    } catch (error) {
      throw new NativeError("launch_at_login_set", `Login item error: ${errorText(error)}`);
    }
    try {
      await writePref(key, value);
    } catch (error) {
      await restore(() => launchAtLoginSet(!value));
      throw error;
    }
    return;
  }
  await writePref(key, value);
  try {
    await windowSetKeepOnTop(value);
  } catch (error) {
    await restore(() => writePref(key, previous));
    throw error;
  }
}

/** The text to show for a failed change: the shell's own words, or the helper's. */
function errorText(error: unknown): string {
  return error instanceof NativeError ? error.message : featureErrorMessage(error);
}

/**
 * The app's own preferences, kept in the helper's database so they follow the
 * user. A change shows at once, is saved through prefs.set and applied to the
 * OS; one that cannot be completed puts the old value back.
 */
export function usePreferences(): PreferencesState {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: PREFS_KEY,
    queryFn: async () => parsePreferences((await rpc("prefs.get")).prefs),
  });
  // The shell's answer; outside the app it fails and the stored preference shows instead.
  const loginItem = useQuery({ queryKey: LOGIN_ITEM_KEY, queryFn: launchAtLoginGet, retry: false });
  const write = useMutation({
    mutationFn: ({ key, value, previous }: { key: BoolPref; value: boolean; previous: boolean }) =>
      applyBool(key, value, previous),
    onMutate: async ({ key, value }) => {
      await queryClient.cancelQueries({ queryKey: PREFS_KEY });
      const previous = queryClient.getQueryData<Preferences>(PREFS_KEY);
      queryClient.setQueryData<Preferences>(PREFS_KEY, (old) => ({ ...(old ?? DEFAULT_PREFERENCES), [key]: value }));
      // Show the new login item at once; settling re-reads what the system holds.
      if (key === "launchAtLogin" && queryClient.getQueryData(LOGIN_ITEM_KEY) !== undefined) {
        queryClient.setQueryData(LOGIN_ITEM_KEY, value);
      }
      return { previous: previous?.[key] ?? DEFAULT_PREFERENCES[key] };
    },
    onError: (_error, { key, value }, context) => {
      // Another change may have landed while this one was in flight; only undo our own.
      queryClient.setQueryData<Preferences>(PREFS_KEY, (old) =>
        old && old[key] === value ? { ...old, [key]: context?.previous ?? DEFAULT_PREFERENCES[key] } : old,
      );
    },
    onSettled: (_data, _error, { key }) => {
      if (key === "launchAtLogin") void queryClient.invalidateQueries({ queryKey: LOGIN_ITEM_KEY });
    },
  });

  const prefs = query.data ?? DEFAULT_PREFERENCES;
  return {
    prefs,
    isLoaded: query.isSuccess,
    loginItemEnabled: loginItem.data,
    errorMessage: write.isError ? `Could not save the setting: ${errorText(write.error)}` : null,
    setBool: (key, value) => write.mutate({ key, value, previous: prefs[key] }),
  };
}
