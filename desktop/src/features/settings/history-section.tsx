"use client";

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ClearHistoryDialog } from "@/features/activity/clear-history-dialog";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import { OptionSelect } from "@/features/activity/option-select";
import { useSettings } from "@/lib/rpc/queries";
import { rpc } from "@/lib/rpc/rpc-client";
import { Note, Outcome, SettingRow, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";
import { useSettingsMutation } from "./use-settings-mutation";

/** Retention choices; the helper's current value is added when it is not one of them. */
const RETENTION_CHOICES = [1, 3, 7, 14, 30, 60, 90];

const dayLabel = (days: number) => (days === 1 ? "1 day" : `${days} days`);

/** The retention choices to offer, always including the helper's current value. */
export function retentionOptions(current: number | undefined): number[] {
  return [...new Set([...RETENTION_CHOICES, ...(current === undefined ? [] : [current])])].sort((a, b) => a - b);
}

/** Settings of the history behind the Activity tab. */
export function HistorySection({ onShowActivity }: { onShowActivity?: () => void }) {
  const settings = useSettings();
  const available = useHelperAvailable();
  const save = useSettingsMutation();
  const [confirmClear, setConfirmClear] = useState(false);
  const clear = useMutation({ mutationFn: () => rpc("access.clear") });

  // The helper reports history settings only from the version that records history.
  const supported = typeof settings.data?.historyEnabled === "boolean";
  const enabled = save.isPending && save.variables.historyEnabled !== undefined
    ? save.variables.historyEnabled
    : (settings.data?.historyEnabled ?? true);
  const days = save.isPending && save.variables.historyRetentionDays !== undefined
    ? save.variables.historyRetentionDays
    : (settings.data?.historyRetentionDays ?? 7);
  const editable = available && supported && !save.isPending;

  return (
    <SettingsSection title="Activity History">
      <SettingRow label="Record activity history">
        <Switch
          aria-label="Record activity history"
          checked={enabled}
          disabled={!editable}
          onCheckedChange={(checked) => save.mutate({ historyEnabled: checked })}
        />
      </SettingRow>
      <SettingRow label="Keep activity history for">
        <OptionSelect
          label="Keep activity history for"
          value={String(days)}
          options={retentionOptions(days).map((d) => ({ value: String(d), label: dayLabel(d) }))}
          disabled={!editable}
          onValueChange={(value) => save.mutate({ historyRetentionDays: Number(value) })}
          className="w-28"
        />
      </SettingRow>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={!available || clear.isPending} onClick={() => setConfirmClear(true)}>
          Clear History
        </Button>
        {onShowActivity ? (
          <Button variant="outline" size="sm" onClick={onShowActivity}>
            Show Activity
          </Button>
        ) : null}
      </div>
      {!available ? (
        <Note tone="warning">Unavailable until the app reconnects to the RouteWise helper.</Note>
      ) : !supported ? (
        <Note tone="warning">Reinstall the helper to record activity history.</Note>
      ) : null}
      <Note>
        These settings govern what the Activity tab shows: the time, domain, address, port, and route of each new
        outbound connection on this Mac, and the DNS answers and routing events RouteWise logs. Records older than the
        retention period are deleted.
      </Note>
      {clear.isSuccess ? (
        <Outcome kind="ok">{`Deleted ${clear.data.deleted} ${clear.data.deleted === 1 ? "entry" : "entries"}.`}</Outcome>
      ) : null}
      {clear.isError ? <Outcome kind="error">{`Could not clear history: ${featureErrorMessage(clear.error)}`}</Outcome> : null}
      {save.isError ? (
        <Outcome kind="error">{`Could not change history settings: ${featureErrorMessage(save.error)}`}</Outcome>
      ) : null}
      <ClearHistoryDialog open={confirmClear} onOpenChange={setConfirmClear} onConfirm={() => clear.mutate()} />
    </SettingsSection>
  );
}
