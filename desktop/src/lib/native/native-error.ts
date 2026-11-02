/** What the shell answers when the user dismisses an administrator prompt or a file dialog. */
export const CANCELLED_MESSAGE = "cancelled";

/** A native command failed. The message is the shell's, already fit to show the user. */
export class NativeError extends Error {
  readonly command: string;

  constructor(command: string, message: string) {
    super(message);
    this.name = "NativeError";
    this.command = command;
  }

  /** True when the user declined, which is not a failure to report. */
  get cancelled(): boolean {
    return this.message === CANCELLED_MESSAGE;
  }
}

/** Whether `error` is the user backing out of a native prompt. */
export function isCancelled(error: unknown): boolean {
  return error instanceof NativeError && error.cancelled;
}

/** Turns whatever a Tauri command rejected with into a `NativeError`. */
export function toNativeError(command: string, value: unknown): NativeError {
  if (value instanceof NativeError) return value;
  const message =
    typeof value === "string" ? value : value instanceof Error ? value.message : `${command} failed`;
  return new NativeError(command, message);
}
