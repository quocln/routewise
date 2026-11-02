"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import type { SetTelemetryParams } from "@/lib/api/types.gen";
import { telemetrySendTestEvent, type TestEventOutcome } from "@/lib/native/native-commands";
import { dsnValidationMessage } from "./telemetry-dsn";
import { Note, Outcome, SettingRow, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";
import { useTelemetry, useTelemetryMutation } from "./use-telemetry";

/** The helper reads a rate of 0 as "unset", so the control starts at 1%; the traces switch is what turns traces off. */
const RATE_MIN = 0.01;
const RATE_MAX = 1;

export const clampRate = (rate: number): number => Math.min(Math.max(rate, RATE_MIN), RATE_MAX);

const TOGGLES = [
  { key: "errors", label: "Errors & crashes" },
  { key: "sessions", label: "Sessions (release health)" },
  { key: "logs", label: "Logs (warnings and errors)" },
  { key: "traces", label: "Performance traces" },
] as const;

/**
 * Settings for sending errors, crashes, sessions, logs and performance traces
 * to the user's own Sentry-compatible server. The DSN is a secret: it is
 * typed into a password field, sent to the helper, and never shown again;
 * only whether one is set is.
 */
export function ErrorReportingSection() {
  const telemetry = useTelemetry();
  const save = useTelemetryMutation();
  const available = useHelperAvailable() && telemetry.isSuccess;
  const current = telemetry.data;
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [rateDraft, setRateDraft] = useState<number | null>(null);
  const [validation, setValidation] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  const hasDsn = current?.hasDsn ?? false;
  const controlsDisabled = !available || !hasDsn || save.isPending;

  const submit = (params: SetTelemetryParams, onDone?: () => void) => {
    setSaved(false);
    save.mutate(params, { onSuccess: onDone, onError: () => setRateDraft(null) });
  };

  const saveDsn = () => {
    const dsn = draft.trim();
    const problem = dsnValidationMessage(dsn);
    if (problem !== undefined || dsn === "") {
      setValidation(problem ?? "Enter a DSN like https://<key>@<host>/<project id>.");
      return;
    }
    setValidation(null);
    // A first DSN switches on errors and crashes, the kind that matters most, so saving it does something.
    const turnOnErrors = !hasDsn && current?.errors === false;
    submit({ dsn, ...(turnOnErrors ? { errors: true } : {}) }, () => {
      setSaved(true);
      stopEditing();
    });
  };

  const stopEditing = () => {
    setEditing(false);
    setDraft("");
    setValidation(null);
  };

  const sendTestEvent = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(testEventMessage(await telemetrySendTestEvent()));
    } catch (error) {
      setTestResult({ kind: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setTesting(false);
    }
  };

  const rate = rateDraft ?? clampRate(current?.tracesSampleRate ?? RATE_MIN);
  const commitRate = () => {
    if (rateDraft !== null) submit({ tracesSampleRate: rateDraft }, () => setRateDraft(null));
  };

  return (
    <SettingsSection title="Error reporting">
      {editing || (!hasDsn && available) ? (
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            saveDsn();
          }}>
          <Input
            type="password"
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="https://<key>@host/<project id>"
            aria-label="DSN"
          />
          <Button type="submit" size="sm" disabled={!available || save.isPending || draft.trim() === ""}>
            Save
          </Button>
          {editing ? (
            <Button type="button" variant="ghost" size="sm" onClick={stopEditing}>
              Cancel
            </Button>
          ) : null}
        </form>
      ) : (
        <SettingRow label="DSN">
          <span className="text-muted-foreground" data-testid="dsn-state">
            {!current ? "Checking..." : hasDsn ? "Set" : "Not set"}
          </span>
          <Button variant="outline" size="sm" disabled={!available} onClick={() => setEditing(true)}>
            Change
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!available || !hasDsn || save.isPending}
            onClick={() => submit({ dsn: "" })}>
            Remove
          </Button>
        </SettingRow>
      )}

      {TOGGLES.map(({ key, label }) => (
        <SettingRow key={key} label={label}>
          <Switch
            aria-label={label}
            checked={current?.[key] ?? false}
            disabled={controlsDisabled}
            onCheckedChange={(checked) => submit({ [key]: checked })}
          />
        </SettingRow>
      ))}

      <SettingRow label="Sample rate">
        <input
          type="range"
          aria-label="Sample rate"
          min={RATE_MIN}
          max={RATE_MAX}
          step={0.01}
          value={rate}
          disabled={controlsDisabled || !current?.traces}
          onChange={(e) => setRateDraft(Number(e.target.value))}
          onPointerUp={commitRate}
          onKeyUp={commitRate}
          className="w-40 accent-primary"
        />
        <span className="w-10 text-right text-xs tabular-nums">{`${Math.round(rate * 100)}%`}</span>
      </SettingRow>

      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={!available || !hasDsn || !current?.errors || testing}
          onClick={() => void sendTestEvent()}>
          {testing ? "Sending..." : "Send test event"}
        </Button>
      </div>

      {!available && telemetry.isError ? (
        <Note tone="warning">{featureErrorMessage(telemetry.error)}</Note>
      ) : !available ? (
        <Note tone="warning">Unavailable until the app reconnects to the RouteWise helper.</Note>
      ) : null}
      <Note>Domains, IPs and VPN names are replaced with [redacted] before sending.</Note>
      {saved ? <Outcome kind="ok">Saved.</Outcome> : null}
      {validation ? <Outcome kind="error">{validation}</Outcome> : null}
      {testResult ? <Outcome kind={testResult.kind}>{testResult.text}</Outcome> : null}
      {save.isError ? <Outcome kind="error">{`Could not save: ${featureErrorMessage(save.error)}`}</Outcome> : null}
    </SettingsSection>
  );
}

/** The wording for each test event outcome. */
export function testEventMessage(result: TestEventOutcome): { kind: "ok" | "error"; text: string } {
  switch (result.outcome) {
    case "sent":
      return { kind: "ok", text: `Test event sent (${result.eventId.slice(0, 8)}). It should appear in your project shortly.` };
    case "notRunning":
      return { kind: "error", text: "Error reporting is not running. Turn on Errors & crashes and save a DSN." };
    case "dropped":
      return { kind: "error", text: "The SDK did not accept the test event." };
  }
}
