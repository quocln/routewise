"use client";

import { getVersion } from "@tauri-apps/api/app";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isTauri } from "@tauri-apps/api/core";
import { CircleArrowDown, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { openReleasePage, updateCheck, type UpdateInfo } from "@/lib/native/native-commands";
import type { NativeError } from "@/lib/native/native-error";
import { Note, Outcome, SettingRow, SettingsSection } from "./settings-section";
import { PREFS_KEY, usePreferences } from "./use-preferences";
import { UPDATE_INFO_KEY, useUpdateInfo } from "./use-update-info";

/** The app's own version, from the Tauri shell; absent outside it. */
function useAppVersion(): string | undefined {
  const query = useQuery({
    queryKey: ["app.version"],
    queryFn: () => (isTauri() ? getVersion() : Promise.resolve(null)),
    staleTime: Infinity,
    retry: false,
  });
  return query.data ?? undefined;
}

/** A release date as the user's locale writes it, or the text itself when it is not a date. */
export function formatPublished(publishedAt: string | null): string | undefined {
  if (publishedAt === null) return undefined;
  const ms = Date.parse(publishedAt);
  return Number.isNaN(ms) ? publishedAt : new Date(ms).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function AvailableUpdate({ info }: { info: UpdateInfo }) {
  const download = useMutation<null, NativeError, string>({ mutationFn: openReleasePage });
  const published = formatPublished(info.publishedAt);
  return (
    <div className="flex flex-col gap-2 rounded-md bg-muted/50 p-3" data-testid="available-update">
      <div className="flex items-center gap-2">
        <CircleArrowDown className="size-5 shrink-0 text-blue-500" aria-hidden />
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="text-sm font-medium">Version {info.latestVersion} available</span>
          {published ? <span className="text-xs text-muted-foreground">{published}</span> : null}
        </div>
        {info.releaseUrl ? (
          <Button size="sm" disabled={download.isPending} onClick={() => download.mutate(info.releaseUrl!)}>
            Download
          </Button>
        ) : null}
      </div>
      {info.notes ? (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-semibold">Release Notes</span>
          <pre className="max-h-40 overflow-auto font-sans text-xs whitespace-pre-wrap text-muted-foreground select-text">
            {info.notes}
          </pre>
        </div>
      ) : null}
      {download.isError ? <Outcome kind="error">{download.error.message}</Outcome> : null}
    </div>
  );
}

/** The app's version, when it last looked for a newer one, and a release it found. */
export function UpdatesSection() {
  const queryClient = useQueryClient();
  const version = useAppVersion();
  const { prefs } = usePreferences();
  const found = useUpdateInfo();
  const check = useMutation<UpdateInfo, NativeError>({
    mutationFn: updateCheck,
    onSuccess: (info) => {
      queryClient.setQueryData(UPDATE_INFO_KEY, info);
      // The shell recorded the time of the check.
      void queryClient.invalidateQueries({ queryKey: PREFS_KEY });
    },
  });
  const upToDate = check.isSuccess && !check.data.updateAvailable;

  return (
    <SettingsSection title="Updates">
      <SettingRow label="Current Version">
        <span className="text-muted-foreground">{version ?? "Unknown"}</span>
      </SettingRow>
      {prefs.lastUpdateCheck ? (
        <SettingRow label="Last Checked">
          <span className="text-muted-foreground">{prefs.lastUpdateCheck.toLocaleString()}</span>
        </SettingRow>
      ) : null}
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={check.isPending} onClick={() => check.mutate()}>
          Check for Updates
        </Button>
        {check.isPending ? (
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
            Checking...
          </span>
        ) : null}
      </div>
      {found?.updateAvailable && found.latestVersion ? <AvailableUpdate info={found} /> : null}
      {upToDate ? (
        <Note>
          {check.data.latestVersion === null ? "No release was found." : "You are running the latest version."}
        </Note>
      ) : null}
      {check.isError ? <Outcome kind="error">{`Could not check for updates: ${check.error.message}`}</Outcome> : null}
    </SettingsSection>
  );
}
