import { isTauri } from "@tauri-apps/api/core";
import { reportUiError } from "./report-ui";

/** Browsers raise this when a layout settles over several frames; it is not a fault. */
const BENIGN_MESSAGES = [/^ResizeObserver loop/];

function describe(reason: unknown): { message: string; stack?: string } {
  if (reason instanceof Error) return { message: `${reason.name}: ${reason.message}`, stack: reason.stack };
  if (typeof reason === "string") return { message: reason };
  try {
    return { message: JSON.stringify(reason) ?? String(reason) };
  } catch {
    return { message: String(reason) };
  }
}

/**
 * Forwards uncaught script errors and unhandled promise rejections to the
 * Rust core. Returns a function that removes the listeners. Installs nothing
 * outside the app.
 */
export function installErrorForwarding(target: Window = window): () => void {
  if (!isTauri()) return () => {};
  const onError = (event: ErrorEvent) => {
    if (BENIGN_MESSAGES.some((pattern) => pattern.test(event.message))) return;
    const stack = event.error instanceof Error ? event.error.stack : undefined;
    reportUiError({ kind: "error", message: event.message || "Unknown error", stack });
  };
  const onRejection = (event: PromiseRejectionEvent) => {
    reportUiError({ kind: "unhandledrejection", ...describe(event.reason) });
  };
  target.addEventListener("error", onError);
  target.addEventListener("unhandledrejection", onRejection);
  return () => {
    target.removeEventListener("error", onError);
    target.removeEventListener("unhandledrejection", onRejection);
  };
}
