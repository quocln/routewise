"use client";

import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { openLogFolder, type LogFolder } from "@/lib/native/native-commands";
import type { NativeError } from "@/lib/native/native-error";
import { Note, Outcome, SettingsSection } from "./settings-section";

/** Buttons that reveal the newest app and helper logs in Finder. */
export function LogsSection() {
  const open = useMutation<null, NativeError, LogFolder>({ mutationFn: openLogFolder });
  return (
    <SettingsSection title="Logs">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" disabled={open.isPending} onClick={() => open.mutate("app")}>
          Open App Logs
        </Button>
        <Button variant="outline" size="sm" disabled={open.isPending} onClick={() => open.mutate("helper")}>
          Open Helper Logs
        </Button>
      </div>
      <Note>
        One file per day, kept for 14 days. App logs are in ~/Library/Logs/RouteWise; helper logs are in /var/log.
      </Note>
      {open.isError ? <Outcome kind="error">{`Could not open the logs: ${open.error.message}`}</Outcome> : null}
    </SettingsSection>
  );
}
