import { nativeInvoke } from "./native-invoke";

/** Whether the helper daemon's launchd service exists and runs. */
export interface HelperServiceStatus {
  installed: boolean;
  running: boolean;
}

/** The latest release as the shell found it. */
export interface UpdateInfo {
  currentVersion: string;
  /** Null when no release was found. */
  latestVersion: string | null;
  updateAvailable: boolean;
  releaseUrl: string | null;
  /** ISO 8601. */
  publishedAt: string | null;
  notes: string | null;
}

/** One reading of this computer's figures. A figure is null until it can be read. */
export interface SystemStatsSample {
  timeMs: number;
  cpuPercent: number | null;
  memoryPercent: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  diskPercent: number | null;
  diskUsedBytes: number | null;
  diskTotalBytes: number | null;
  /** Bytes per second over the last sample, across physical interfaces. */
  network: { up: number; down: number } | null;
}

/** The latest five minutes of samples, oldest first. */
export function systemStatsHistory(): Promise<SystemStatsSample[]> {
  return nativeInvoke<SystemStatsSample[]>("system_stats_history");
}

/** A file the user picked and the shell read. */
export interface OpenedTextFile {
  name: string;
  contents: string;
}

export interface FileFilter {
  filterName: string;
  extensions: string[];
}

export type LogFolder = "app" | "helper";

export const helperServiceStatus = () => nativeInvoke<HelperServiceStatus>("helper_service_status");

/** Installs the helper, or reinstalls it when present. Asks for an administrator password. */
export const helperInstall = () => nativeInvoke<null>("helper_install");

export const helperUninstall = () => nativeInvoke<null>("helper_uninstall");

/** The login item as the OS holds it. */
export const launchAtLoginGet = () => nativeInvoke<boolean>("launch_at_login_get");

export const launchAtLoginSet = (enabled: boolean) => nativeInvoke<null>("launch_at_login_set", { enabled });

/** Applies the keep-on-top setting to the open main window. */
export const windowSetKeepOnTop = (enabled: boolean) => nativeInvoke<null>("window_set_keep_on_top", { enabled });

/** Reveals the newest log of `which` in Finder. */
export const openLogFolder = (which: LogFolder) => nativeInvoke<null>("open_log_folder", { which });

/** Shows a save dialog; resolves to the saved file's name, or null when the user cancelled. */
export const saveTextFile = (defaultName: string, contents: string, filter: FileFilter) =>
  nativeInvoke<string | null>("save_text_file", { defaultName, contents, ...filter });

/** Shows an open dialog; resolves to the file, or null when the user cancelled. */
export const openTextFile = (filter: FileFilter) => nativeInvoke<OpenedTextFile | null>("open_text_file", { ...filter });

/** Asks GitHub for the latest release; the shell records the time of the check. */
export const updateCheck = () => nativeInvoke<UpdateInfo>("update_check");

/** The newest check result the shell holds since launch (automatic checks included), or null. */
export const updateLastResult = () => nativeInvoke<UpdateInfo | null>("update_last_result");

/** Opens a RouteWise release page in the browser. */
export const openReleasePage = (url: string) => nativeInvoke<null>("open_release_page", { url });

/** What happened to a test event sent to the error reporting server. */
export type TestEventOutcome = { outcome: "sent"; eventId: string } | { outcome: "notRunning" } | { outcome: "dropped" };

/** Sends a harmless event to check the error reporting DSN end to end. */
export const telemetrySendTestEvent = () => nativeInvoke<TestEventOutcome>("telemetry_send_test_event");
