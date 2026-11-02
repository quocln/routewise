import { describe, expect, it } from "vitest";
import { TransferError, defaultFileName, parseConfigDocument, prettyPrint } from "./config-transfer";
import { retentionOptions } from "./history-section";
import { DEFAULT_PREFERENCES, parsePreferences } from "./preferences";
import { dsnValidationMessage } from "./telemetry-dsn";
import { clampRate } from "./error-reporting-section";
import { helperState } from "./helper-section";
import { toTelemetryView } from "./use-telemetry";

describe("config transfer", () => {
  it("names the file after the local day", () => {
    expect(defaultFileName(new Date(2026, 9, 29, 23, 59))).toBe("routewise-config-20261029.json");
    expect(defaultFileName(new Date(2026, 0, 5))).toBe("routewise-config-20260105.json");
  });

  it("prints readable JSON with sorted keys", () => {
    expect(prettyPrint({ b: 1, a: { d: [{ z: 1, y: 2 }], c: null } })).toBe(
      '{\n  "a": {\n    "c": null,\n    "d": [\n      {\n        "y": 2,\n        "z": 1\n      }\n    ]\n  },\n  "b": 1\n}\n',
    );
  });

  it("rejects what cannot be a config object", () => {
    expect(() => parseConfigDocument("not json")).toThrow(new TransferError("The file is not valid JSON."));
    for (const text of ["[1]", "null", "3", '"x"']) {
      expect(() => parseConfigDocument(text)).toThrow("The file is not a RouteWise config export.");
    }
    expect(parseConfigDocument('{"format":"routewise-config"}')).toEqual({ format: "routewise-config" });
  });
});

describe("DSN validation", () => {
  it("accepts a DSN and an empty value", () => {
    expect(dsnValidationMessage("https://abc@sentry.example.com/12")).toBeUndefined();
    expect(dsnValidationMessage("http://abc:pw@host:9000/a/12")).toBeUndefined();
    expect(dsnValidationMessage("   ")).toBeUndefined();
  });

  it("explains a malformed DSN without repeating it", () => {
    for (const bad of ["nonsense", "ftp://k@h/1", "https://host/1", "https://@host/1"]) {
      const message = dsnValidationMessage(bad);
      expect(message).toBe("Enter a DSN like https://<key>@<host>/<project id>.");
    }
    expect(dsnValidationMessage("https://key@host")).toBe("The DSN needs a project id at the end.");
  });
});

describe("telemetry view", () => {
  it("keeps whether a DSN is set and nothing of the DSN", () => {
    const view = toTelemetryView({
      dsn: "https://secret@host/1", errors: true, sessions: false, logs: false, traces: false, tracesSampleRate: 0.5,
    });
    expect(view.hasDsn).toBe(true);
    expect(JSON.stringify(view)).not.toContain("secret");
    expect(toTelemetryView({ ...view, dsn: "" }).hasDsn).toBe(false);
  });

  it("keeps the sample rate within what the helper reads as set", () => {
    expect(clampRate(0)).toBe(0.01);
    expect(clampRate(7)).toBe(1);
    expect(clampRate(0.4)).toBe(0.4);
  });
});

describe("preferences", () => {
  it("reads the stored values", () => {
    expect(
      parsePreferences({ launchAtLogin: true, keepWindowOnTop: false, lastUpdateCheck: "2026-10-28T09:30:15Z" }),
    ).toEqual({ launchAtLogin: true, keepWindowOnTop: false, lastUpdateCheck: new Date("2026-10-28T09:30:15Z") });
  });

  it("falls back to the defaults for a missing or mistyped value", () => {
    expect(parsePreferences(undefined)).toEqual(DEFAULT_PREFERENCES);
    expect(parsePreferences({ launchAtLogin: "yes", keepWindowOnTop: 1, lastUpdateCheck: "yesterday" })).toEqual(
      DEFAULT_PREFERENCES,
    );
  });
});

describe("history and helper presentation", () => {
  it("offers the helper's own retention when it is not a standard choice", () => {
    expect(retentionOptions(undefined)).toEqual([1, 3, 7, 14, 30, 60, 90]);
    expect(retentionOptions(10)).toEqual([1, 3, 7, 10, 14, 30, 60, 90]);
  });

  it("describes the helper", () => {
    expect(helperState(undefined, true).label).toBe("Not reachable");
    expect(helperState(undefined, false).label).toBe("Checking...");
    expect(helperState({ running: false }, false).label).toBe("Stopped");
    expect(helperState({ running: true, degraded: true }, false).label).toBe("Needs attention");
    expect(helperState({ running: true }, false).label).toBe("Running");
  });
});
