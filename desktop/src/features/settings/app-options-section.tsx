"use client";

import { Switch } from "@/components/ui/switch";
import { Note, Outcome, SettingRow, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";
import { usePreferences } from "./use-preferences";

/** Startup and window preferences. A change is saved, then applied to the OS by the shell. */
export function AppOptionsSection() {
  const { prefs, isLoaded, loginItemEnabled, errorMessage, setBool } = usePreferences();
  const editable = useHelperAvailable() && isLoaded;
  return (
    <>
      <SettingsSection title="Startup">
        <SettingRow label="Launch at Login">
          <Switch
            aria-label="Launch at Login"
            // The system's login item is the truth; the stored preference shows when it cannot be read.
            checked={loginItemEnabled ?? prefs.launchAtLogin}
            disabled={!editable}
            onCheckedChange={(checked) => setBool("launchAtLogin", checked)}
          />
        </SettingRow>
      </SettingsSection>
      <SettingsSection title="Window">
        <SettingRow label="Keep RouteWise on Top">
          <Switch
            aria-label="Keep RouteWise on Top"
            checked={prefs.keepWindowOnTop}
            disabled={!editable}
            onCheckedChange={(checked) => setBool("keepWindowOnTop", checked)}
          />
        </SettingRow>
        <Note>
          Floats the window above other apps, so a route check stays visible while you work in a browser or terminal.
        </Note>
        {errorMessage ? <Outcome kind="error">{errorMessage}</Outcome> : null}
      </SettingsSection>
    </>
  );
}
