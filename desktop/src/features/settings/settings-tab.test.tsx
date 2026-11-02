import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const SECRET = "https://topsecretkey@errors.example.com/42";
type Reply = unknown | ((params: unknown) => unknown);
const replies: Record<string, Reply> = {};
const calls: { method: string; params: unknown }[] = [];
// The shell's own commands, by name; a failure is an Error whose message the shell would send.
const natives: Record<string, Reply> = {};
const nativeCalls: { command: string; args: unknown }[] = [];

function answer(table: Record<string, Reply>, key: string, params: unknown, fail: (message: string) => unknown) {
  const reply = table[key];
  const value = typeof reply === "function" ? (reply as (p: unknown) => unknown)(params) : reply;
  return value instanceof Error ? Promise.reject(fail(value.message)) : Promise.resolve(value);
}

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: (cmd: string, args: { method: string; params: unknown } | undefined) => {
    if (cmd !== "rpc") {
      nativeCalls.push({ command: cmd, args });
      if (!(cmd in natives)) return Promise.reject(`unexpected ${cmd}`);
      return answer(natives, cmd, args, (message) => message);
    }
    calls.push(args!);
    if (!(args!.method in replies)) {
      return Promise.reject({ kind: "remote", code: -32601, message: "method not found" });
    }
    return answer(replies, args!.method, args!.params, (message) => ({ kind: "remote", code: -32000, message }));
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => {}) }));
vi.mock("@tauri-apps/api/app", () => ({ getVersion: () => Promise.resolve("0.1.0") }));

const { SettingsTab } = await import("./settings-tab");

const settings = { useVpnDns: false, allowIpv6: false, allowedVpnClients: [], historyEnabled: true, historyRetentionDays: 7 };
const callsTo = (method: string) => calls.filter((c) => c.method === method);
const nativeCallsTo = (command: string) => nativeCalls.filter((c) => c.command === command);

beforeEach(() => {
  calls.length = 0;
  nativeCalls.length = 0;
  for (const key of Object.keys(replies)) delete replies[key];
  for (const key of Object.keys(natives)) delete natives[key];
  natives["helper_service_status"] = { installed: true, running: true };
  natives["launch_at_login_get"] = false;
  replies["status.get"] = { running: true, vpnConnected: false, routeCount: 0 };
  replies["settings.get"] = { ...settings };
  replies["telemetry.get"] = { dsn: SECRET, errors: true, sessions: false, logs: false, traces: true, tracesSampleRate: 0.25 };
  replies["prefs.get"] = { prefs: { launchAtLogin: false, keepWindowOnTop: true } };
});

function renderTab(props: { onShowActivity?: () => void } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { client, ...render(
    <QueryClientProvider client={client}>
      <SettingsTab {...props} />
    </QueryClientProvider>,
  ) };
}

const enabledSwitch = async (name: string) => {
  const control = await screen.findByRole("switch", { name });
  await waitFor(() => expect(control).not.toHaveAttribute("aria-disabled", "true"));
  return control;
};

describe("SettingsTab", () => {
  it("shows the helper's state and the app version", async () => {
    renderTab();
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(await screen.findByText("0.1.0")).toBeInTheDocument();
  });

  it("changes IPv6 through the helper and keeps the answer", async () => {
    const user = userEvent.setup();
    replies["settings.set"] = { ...settings, allowIpv6: true };
    renderTab();
    const toggle = await enabledSwitch("Allow IPv6 for listed domains");
    expect(toggle).not.toBeChecked();
    await user.click(toggle);
    await waitFor(() => expect(callsTo("settings.set")[0]?.params).toEqual({ allowIpv6: true }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Allow IPv6 for listed domains" })).toBeChecked());
  });

  it("reports a refused IPv6 change", async () => {
    const user = userEvent.setup();
    replies["settings.set"] = new Error("not allowed");
    renderTab();
    await user.click(await enabledSwitch("Allow IPv6 for listed domains"));
    expect(await screen.findByText("Could not change IPv6: not allowed")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Allow IPv6 for listed domains" })).not.toBeChecked();
  });

  it("says a helper without the IPv6 setting needs updating", async () => {
    replies["settings.get"] = { useVpnDns: false, allowedVpnClients: [], historyEnabled: true, historyRetentionDays: 7 };
    renderTab();
    expect(await screen.findByText("Needs a newer RouteWise helper.")).toBeInTheDocument();
  });

  it("turns history recording off", async () => {
    const user = userEvent.setup();
    replies["settings.set"] = { ...settings, historyEnabled: false };
    renderTab();
    await user.click(await enabledSwitch("Record activity history"));
    await waitFor(() => expect(callsTo("settings.set")[0]?.params).toEqual({ historyEnabled: false }));
  });

  it("deletes the history only after confirmation and reports the count", async () => {
    const user = userEvent.setup();
    replies["access.clear"] = { deleted: 1 };
    renderTab();
    const button = screen.getAllByRole("button", { name: "Clear History" })[0];
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(callsTo("access.clear")).toHaveLength(0);
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(callsTo("access.clear")).toHaveLength(0);
    await user.click(screen.getAllByRole("button", { name: "Clear History" })[0]);
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Clear History" }));
    expect(await screen.findByText("Deleted 1 entry.")).toBeInTheDocument();
  });

  it("clears the DNS cache without asking, since no route changes", async () => {
    const user = userEvent.setup();
    replies["dns.clearCache"] = { success: true };
    renderTab();
    const button = await screen.findByRole("button", { name: "Clear DNS Cache" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(await screen.findByText("DNS cache cleared.")).toBeInTheDocument();
    expect(callsTo("dns.clearCache")).toHaveLength(1);
    expect(callsTo("dns.clean")).toHaveLength(0);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("cleans DNS only after confirmation and reports the routes removed", async () => {
    const user = userEvent.setup();
    replies["dns.clean"] = { routesRemoved: 1 };
    renderTab();
    const button = await screen.findByRole("button", { name: "Clean DNS" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(callsTo("dns.clean")).toHaveLength(0);
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
    expect(callsTo("dns.clean")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Clean DNS" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Clean DNS" }));
    expect(await screen.findByText("DNS cleaned. Removed 1 learned route.")).toBeInTheDocument();
    expect(callsTo("dns.clean")).toHaveLength(1);
  });

  it("reports a DNS cache flush that failed", async () => {
    const user = userEvent.setup();
    replies["dns.clearCache"] = new Error("the system's was not cleared");
    renderTab();
    const button = await screen.findByRole("button", { name: "Clear DNS Cache" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not clear the DNS cache");
  });

  it("offers Show Activity only when the shell can show it", async () => {
    const onShowActivity = vi.fn();
    const user = userEvent.setup();
    const { unmount } = renderTab({ onShowActivity });
    await user.click(await screen.findByRole("button", { name: "Show Activity" }));
    expect(onShowActivity).toHaveBeenCalled();
    unmount();
    renderTab();
    await screen.findByText("Running");
    expect(screen.queryByRole("button", { name: "Show Activity" })).toBeNull();
  });
});

describe("error reporting", () => {
  it("never shows the DSN, only that one is set", async () => {
    const { container } = renderTab();
    await waitFor(() => expect(screen.getByTestId("dsn-state")).toHaveTextContent(/^Set$/));
    expect(container.innerHTML).not.toContain("topsecretkey");
    expect(screen.queryByDisplayValue(SECRET)).toBeNull();
  });

  it("takes a new DSN in a password field and empties it after saving", async () => {
    const user = userEvent.setup();
    replies["telemetry.set"] = { dsn: SECRET, errors: true, sessions: false, logs: false, traces: true, tracesSampleRate: 0.25 };
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Change" }));
    const field = screen.getByLabelText("DSN");
    expect(field).toHaveAttribute("type", "password");
    await user.type(field, "not a dsn");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Enter a DSN like https://<key>@<host>/<project id>.")).toBeInTheDocument();
    expect(callsTo("telemetry.set")).toHaveLength(0);
    await user.clear(field);
    await user.type(field, "https://newkey@errors.example.com/7");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(callsTo("telemetry.set")[0]?.params).toEqual({ dsn: "https://newkey@errors.example.com/7" }));
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    expect(screen.queryByLabelText("DSN")).toBeNull();
    expect(screen.queryByDisplayValue("https://newkey@errors.example.com/7")).toBeNull();
  });

  it("switches on errors with the first DSN", async () => {
    const user = userEvent.setup();
    replies["telemetry.get"] = { dsn: "", errors: false, sessions: false, logs: false, traces: false, tracesSampleRate: 0 };
    replies["telemetry.set"] = { dsn: SECRET, errors: true, sessions: false, logs: false, traces: false, tracesSampleRate: 0 };
    renderTab();
    await user.type(await screen.findByLabelText("DSN"), "https://k@errors.example.com/1");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(callsTo("telemetry.set")[0]?.params).toEqual({ dsn: "https://k@errors.example.com/1", errors: true }),
    );
  });

  it("removes the DSN and toggles a kind", async () => {
    const user = userEvent.setup();
    replies["telemetry.set"] = (params: unknown) => ({
      dsn: (params as { dsn?: string }).dsn === "" ? "" : SECRET,
      errors: true, sessions: true, logs: false, traces: true, tracesSampleRate: 0.25,
    });
    renderTab();
    await user.click(await enabledSwitch("Sessions (release health)"));
    await waitFor(() => expect(callsTo("telemetry.set")[0]?.params).toEqual({ sessions: true }));
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    await waitFor(() => expect(callsTo("telemetry.set")[1]?.params).toEqual({ dsn: "" }));
    expect(await screen.findByLabelText("DSN")).toHaveAttribute("type", "password");
  });

  it("disables the kinds until a DSN is set", async () => {
    replies["telemetry.get"] = { dsn: "", errors: false, sessions: false, logs: false, traces: false, tracesSampleRate: 0 };
    renderTab();
    await screen.findByLabelText("DSN");
    expect(screen.getByRole("switch", { name: "Errors & crashes" })).toHaveAttribute("aria-disabled", "true");
  });
});

describe("app options", () => {
  it("saves a preference and puts the old value back when refused", async () => {
    const user = userEvent.setup();
    replies["prefs.set"] = new Error("nope");
    renderTab();
    const toggle = await enabledSwitch("Keep RouteWise on Top");
    expect(toggle).toBeChecked();
    await user.click(toggle);
    await waitFor(() => expect(callsTo("prefs.set")[0]?.params).toEqual({ key: "keepWindowOnTop", value: false }));
    expect(await screen.findByText("Could not save the setting: nope")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("switch", { name: "Keep RouteWise on Top" })).toBeChecked());
    expect(nativeCallsTo("window_set_keep_on_top")).toHaveLength(0);
  });

  it("saves keep-on-top, then applies it to the window", async () => {
    const user = userEvent.setup();
    replies["prefs.set"] = { success: true };
    natives["window_set_keep_on_top"] = null;
    renderTab();
    await user.click(await enabledSwitch("Keep RouteWise on Top"));
    await waitFor(() => expect(nativeCallsTo("window_set_keep_on_top")[0]?.args).toEqual({ enabled: false }));
    expect(callsTo("prefs.set")[0]?.params).toEqual({ key: "keepWindowOnTop", value: false });
    expect(screen.getByRole("switch", { name: "Keep RouteWise on Top" })).not.toBeChecked();
  });

  it("puts keep-on-top back in the store when the window cannot change", async () => {
    const user = userEvent.setup();
    replies["prefs.set"] = { success: true };
    natives["window_set_keep_on_top"] = new Error("no window");
    renderTab();
    await user.click(await enabledSwitch("Keep RouteWise on Top"));
    expect(await screen.findByText("Could not save the setting: no window")).toBeInTheDocument();
    await waitFor(() => expect(callsTo("prefs.set").map((c) => c.params)).toEqual([
      { key: "keepWindowOnTop", value: false },
      { key: "keepWindowOnTop", value: true },
    ]));
    expect(screen.getByRole("switch", { name: "Keep RouteWise on Top" })).toBeChecked();
  });

  it("changes the login item, then stores the preference, and shows the OS state", async () => {
    const user = userEvent.setup();
    let os = false;
    natives["launch_at_login_get"] = () => os;
    natives["launch_at_login_set"] = (args: unknown) => {
      os = (args as { enabled: boolean }).enabled;
      return null;
    };
    replies["prefs.set"] = { success: true };
    renderTab();
    await user.click(await enabledSwitch("Launch at Login"));
    await waitFor(() => expect(callsTo("prefs.set")[0]?.params).toEqual({ key: "launchAtLogin", value: true }));
    expect(nativeCallsTo("launch_at_login_set")[0]?.args).toEqual({ enabled: true });
    await waitFor(() => expect(nativeCallsTo("launch_at_login_get").length).toBeGreaterThan(1));
    expect(screen.getByRole("switch", { name: "Launch at Login" })).toBeChecked();
  });

  it("shows the OS login item even when the stored preference disagrees", async () => {
    natives["launch_at_login_get"] = true;
    renderTab();
    await enabledSwitch("Launch at Login");
    await waitFor(() => expect(screen.getByRole("switch", { name: "Launch at Login" })).toBeChecked());
  });

  it("reverts and reports a login item the OS refused, without storing it", async () => {
    const user = userEvent.setup();
    natives["launch_at_login_set"] = new Error("not permitted");
    renderTab();
    await user.click(await enabledSwitch("Launch at Login"));
    expect(await screen.findByText("Could not save the setting: Login item error: not permitted")).toBeInTheDocument();
    expect(callsTo("prefs.set")).toHaveLength(0);
    await waitFor(() => expect(screen.getByRole("switch", { name: "Launch at Login" })).not.toBeChecked());
  });

  it("puts the login item back when the preference is refused", async () => {
    const user = userEvent.setup();
    natives["launch_at_login_set"] = null;
    replies["prefs.set"] = new Error("nope");
    renderTab();
    await user.click(await enabledSwitch("Launch at Login"));
    expect(await screen.findByText("Could not save the setting: nope")).toBeInTheDocument();
    await waitFor(() => expect(nativeCallsTo("launch_at_login_set").map((c) => c.args)).toEqual([
      { enabled: true },
      { enabled: false },
    ]));
  });
});

describe("helper", () => {
  const button = (name: string) => screen.findByRole("button", { name });

  it("shows whether the helper is installed", async () => {
    renderTab();
    expect(await screen.findByTestId("helper-installed")).toHaveTextContent("Installed");
    expect(await button("Reinstall Helper")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Uninstall Helper" })).toBeEnabled();
  });

  it("offers only Install when the helper is missing, and says why it is not reachable", async () => {
    natives["helper_service_status"] = { installed: false, running: false };
    delete replies["status.get"];
    renderTab();
    expect(await button("Install Helper")).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Uninstall Helper" })).toBeNull();
    await waitFor(() => expect(screen.getByTestId("helper-state")).toHaveTextContent("Not installed"));
  });

  it("installs and refreshes the helper's status", async () => {
    const user = userEvent.setup();
    natives["helper_install"] = null;
    renderTab();
    await screen.findByText("Running");
    const before = callsTo("status.get").length;
    await user.click(await button("Reinstall Helper"));
    await waitFor(() => expect(nativeCallsTo("helper_install")).toHaveLength(1));
    await waitFor(() => expect(callsTo("status.get").length).toBeGreaterThan(before));
  });

  it("does not report a declined administrator prompt", async () => {
    const user = userEvent.setup();
    natives["helper_install"] = new Error("cancelled");
    renderTab();
    await user.click(await button("Reinstall Helper"));
    await waitFor(() => expect(nativeCallsTo("helper_install")).toHaveLength(1));
    await waitFor(() => expect(screen.getByRole("button", { name: "Reinstall Helper" })).toBeEnabled());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reports an install that failed", async () => {
    const user = userEvent.setup();
    natives["helper_install"] = new Error("The bundled helper is missing.");
    renderTab();
    await user.click(await button("Reinstall Helper"));
    expect(await screen.findByText("The bundled helper is missing.")).toBeInTheDocument();
  });

  it("uninstalls only after confirmation", async () => {
    const user = userEvent.setup();
    natives["helper_uninstall"] = null;
    renderTab();
    await user.click(await button("Uninstall Helper"));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(nativeCallsTo("helper_uninstall")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Uninstall Helper" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Uninstall" }));
    await waitFor(() => expect(nativeCallsTo("helper_uninstall")).toHaveLength(1));
  });
});

describe("updates", () => {
  const info = {
    currentVersion: "0.1.0",
    latestVersion: "0.2.0",
    updateAvailable: true,
    releaseUrl: "https://github.com/quocln/routewise/releases/tag/v0.2.0",
    publishedAt: "2026-10-01T00:00:00Z",
    notes: "Fixes the thing.",
  };

  it("checks, shows the release and its notes, and opens the release page", async () => {
    const user = userEvent.setup();
    natives["update_check"] = info;
    natives["open_release_page"] = null;
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Check for Updates" }));
    expect(await screen.findByText("Version 0.2.0 available")).toBeInTheDocument();
    expect(screen.getByText("Fixes the thing.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Download" }));
    await waitFor(() => expect(nativeCallsTo("open_release_page")[0]?.args).toEqual({ url: info.releaseUrl }));
  });

  it("says when the app is current, or no release exists", async () => {
    const user = userEvent.setup();
    natives["update_check"] = { ...info, latestVersion: "0.1.0", updateAvailable: false };
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Check for Updates" }));
    expect(await screen.findByText("You are running the latest version.")).toBeInTheDocument();
    expect(screen.queryByTestId("available-update")).toBeNull();
    natives["update_check"] = { ...info, latestVersion: null, updateAvailable: false };
    await user.click(screen.getByRole("button", { name: "Check for Updates" }));
    expect(await screen.findByText("No release was found.")).toBeInTheDocument();
  });

  it("reports a failed check", async () => {
    const user = userEvent.setup();
    natives["update_check"] = new Error("GitHub answered HTTP 403");
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Check for Updates" }));
    expect(await screen.findByText("Could not check for updates: GitHub answered HTTP 403")).toBeInTheDocument();
  });

  it("shows the last check from the stored preference and the app's version", async () => {
    replies["prefs.get"] = { prefs: { lastUpdateCheck: "2026-10-28T10:00:00Z" } };
    renderTab();
    expect(await screen.findByText("Last Checked")).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
  });
});

describe("logs", () => {
  it("opens each log folder", async () => {
    const user = userEvent.setup();
    natives["open_log_folder"] = null;
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Open App Logs" }));
    await waitFor(() => expect(nativeCallsTo("open_log_folder")[0]?.args).toEqual({ which: "app" }));
    await user.click(screen.getByRole("button", { name: "Open Helper Logs" }));
    await waitFor(() => expect(nativeCallsTo("open_log_folder")[1]?.args).toEqual({ which: "helper" }));
  });

  it("reports a folder that cannot be opened", async () => {
    const user = userEvent.setup();
    natives["open_log_folder"] = new Error("There are no logs yet.");
    renderTab();
    await user.click(await screen.findByRole("button", { name: "Open App Logs" }));
    expect(await screen.findByText("Could not open the logs: There are no logs yet.")).toBeInTheDocument();
  });
});

describe("configuration", () => {
  const importButton = async () => {
    await screen.findByText("Running");
    await waitFor(() => expect(screen.getByRole("button", { name: "Import…" })).toBeEnabled());
    return screen.getByRole("button", { name: "Import…" });
  };

  it("asks before an import replaces the configuration, then applies it", async () => {
    const user = userEvent.setup();
    natives["open_text_file"] = { name: "mine.json", contents: '{"format":"routewise-config","version":1}' };
    replies["config.import"] = { restartRequired: true };
    renderTab();
    await user.click(await importButton());
    expect(nativeCallsTo("open_text_file")[0]?.args).toEqual({ filterName: "JSON", extensions: ["json"] });
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Import mine.json?");
    expect(callsTo("config.import")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Replace" }));
    expect(await screen.findByText("Imported mine.json.")).toBeInTheDocument();
    expect(callsTo("config.import")[0]?.params).toEqual({ config: { format: "routewise-config", version: 1 } });
    expect(screen.getByText(/sudo routewise restart/)).toBeInTheDocument();
  });

  it("does nothing when the open dialog is cancelled", async () => {
    const user = userEvent.setup();
    natives["open_text_file"] = null;
    renderTab();
    await user.click(await importButton());
    await waitFor(() => expect(nativeCallsTo("open_text_file")).toHaveLength(1));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("rejects a file that is not a config object without asking the helper", async () => {
    const user = userEvent.setup();
    natives["open_text_file"] = { name: "list.json", contents: "[1,2]" };
    renderTab();
    await user.click(await importButton());
    expect(await screen.findByText("Could not read list.json: The file is not a RouteWise config export.")).toBeInTheDocument();
    natives["open_text_file"] = { name: "bad.json", contents: "{nope" };
    await user.click(screen.getByRole("button", { name: "Import…" }));
    expect(await screen.findByText("Could not read bad.json: The file is not valid JSON.")).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(callsTo("config.import")).toHaveLength(0);
  });

  it("saves the exported configuration through the save dialog", async () => {
    const user = userEvent.setup();
    replies["config.export"] = { version: 1, format: "routewise-config" };
    natives["save_text_file"] = "routewise-config-20261029.json";
    renderTab();
    await waitFor(() => expect(screen.getByRole("button", { name: "Export…" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Export…" }));
    expect(await screen.findByText("Exported to routewise-config-20261029.json.")).toBeInTheDocument();
    const args = nativeCallsTo("save_text_file")[0]?.args as Record<string, unknown>;
    expect(args).toMatchObject({
      contents: '{\n  "format": "routewise-config",\n  "version": 1\n}\n',
      filterName: "JSON",
      extensions: ["json"],
    });
    expect(args.defaultName).toMatch(/^routewise-config-\d{8}\.json$/);
  });

  it("says nothing when the save dialog is cancelled", async () => {
    const user = userEvent.setup();
    replies["config.export"] = { format: "routewise-config" };
    natives["save_text_file"] = null;
    renderTab();
    await waitFor(() => expect(screen.getByRole("button", { name: "Export…" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Export…" }));
    await waitFor(() => expect(nativeCallsTo("save_text_file")).toHaveLength(1));
    expect(screen.queryByText(/^Exported/)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reports an export the helper refused, and never opens the save dialog", async () => {
    const user = userEvent.setup();
    replies["config.export"] = new Error("unauthorized");
    renderTab();
    await waitFor(() => expect(screen.getByRole("button", { name: "Export…" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Export…" }));
    expect(await screen.findByText("Could not export: unauthorized")).toBeInTheDocument();
    expect(nativeCallsTo("save_text_file")).toHaveLength(0);
  });

  it("reports a file that could not be saved", async () => {
    const user = userEvent.setup();
    replies["config.export"] = { format: "routewise-config" };
    natives["save_text_file"] = new Error("Could not write the file.");
    renderTab();
    await waitFor(() => expect(screen.getByRole("button", { name: "Export…" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Export…" }));
    expect(await screen.findByText("Could not export: Could not write the file.")).toBeInTheDocument();
  });
});
