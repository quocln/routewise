import { invoke, isTauri } from "@tauri-apps/api/core";
import { NativeError, toNativeError } from "./native-error";

/**
 * Calls a command of the app's Rust shell. Outside the app (browser dev,
 * tests) there is no shell, so the call rejects with a `NativeError` instead
 * of reaching for a missing bridge.
 */
export async function nativeInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    throw new NativeError(command, "This needs the RouteWise app.");
  }
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toNativeError(command, error);
  }
}
