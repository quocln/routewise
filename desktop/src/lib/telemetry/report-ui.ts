import { invoke, isTauri } from "@tauri-apps/api/core";

/** What the webview tells the Rust core about an error it caught. */
export interface UiErrorReport {
  kind: "error" | "unhandledrejection" | "render";
  message: string;
  stack?: string;
  componentStack?: string;
}

export type UiLogLevel = "warn" | "error";

/**
 * Sends a caught error to the Rust core, which scrubs it and reports it when
 * error reporting is on. Never throws or rejects: reporting a failure must not
 * cause another one. Does nothing outside the app (browser dev, tests).
 */
export function reportUiError(report: UiErrorReport): void {
  if (!isTauri()) return;
  invoke("report_ui_error", { report }).catch(() => {
    // Nowhere left to report to.
  });
}

/**
 * Writes a line to the app log file (and to reporting logs when they are on)
 * through the Rust core. Never throws or rejects.
 */
export function logUi(level: UiLogLevel, message: string): void {
  if (!isTauri()) return;
  invoke("log_ui", { entry: { level, message } }).catch(() => {
    // Nowhere left to log to.
  });
}
