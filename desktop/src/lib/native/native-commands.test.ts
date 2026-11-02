import { beforeEach, describe, expect, it, vi } from "vitest";

let inTauri = true;
const invoke = vi.fn();
const listen = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => inTauri, invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: (...args: unknown[]) => listen(...args) }));

const commands = await import("./native-commands");
const { NativeError, isCancelled } = await import("./native-error");
const { UPDATES_AVAILABLE_EVENT, listenUpdatesAvailable } = await import("./update-events");

beforeEach(() => {
  inTauri = true;
  invoke.mockReset();
  listen.mockReset();
});

describe("native commands", () => {
  it.each([
    ["helper_service_status", () => commands.helperServiceStatus(), undefined],
    ["helper_install", () => commands.helperInstall(), undefined],
    ["helper_uninstall", () => commands.helperUninstall(), undefined],
    ["launch_at_login_get", () => commands.launchAtLoginGet(), undefined],
    ["launch_at_login_set", () => commands.launchAtLoginSet(true), { enabled: true }],
    ["window_set_keep_on_top", () => commands.windowSetKeepOnTop(false), { enabled: false }],
    ["open_log_folder", () => commands.openLogFolder("helper"), { which: "helper" }],
    [
      "save_text_file",
      () => commands.saveTextFile("a.json", "{}", { filterName: "JSON", extensions: ["json"] }),
      { defaultName: "a.json", contents: "{}", filterName: "JSON", extensions: ["json"] },
    ],
    [
      "open_text_file",
      () => commands.openTextFile({ filterName: "JSON", extensions: ["json"] }),
      { filterName: "JSON", extensions: ["json"] },
    ],
    ["update_check", () => commands.updateCheck(), undefined],
    ["update_last_result", () => commands.updateLastResult(), undefined],
    ["telemetry_send_test_event", () => commands.telemetrySendTestEvent(), undefined],
    ["open_release_page", () => commands.openReleasePage("https://github.com/quocln/routewise/releases"), {
      url: "https://github.com/quocln/routewise/releases",
    }],
  ])("%s is invoked by name with its arguments", async (name, call, args) => {
    invoke.mockResolvedValue(null);
    await call();
    expect(invoke).toHaveBeenCalledWith(name, args);
  });

  it("returns what the shell answers", async () => {
    invoke.mockResolvedValue({ installed: true, running: false });
    await expect(commands.helperServiceStatus()).resolves.toEqual({ installed: true, running: false });
  });

  it("rejects with the shell's message", async () => {
    invoke.mockRejectedValue("disk is full");
    await expect(commands.helperInstall()).rejects.toMatchObject({ name: "NativeError", message: "disk is full" });
  });

  it("recognises a cancelled prompt", async () => {
    invoke.mockRejectedValue("cancelled");
    const error = await commands.helperInstall().catch((e: unknown) => e);
    expect(isCancelled(error)).toBe(true);
    expect(isCancelled(new NativeError("x", "other"))).toBe(false);
    expect(isCancelled(new Error("cancelled"))).toBe(false);
  });

  it("rejects without calling the bridge outside the app", async () => {
    inTauri = false;
    await expect(commands.launchAtLoginGet()).rejects.toBeInstanceOf(NativeError);
    expect(invoke).not.toHaveBeenCalled();
  });
});

describe("listenUpdatesAvailable", () => {
  it("passes each payload on and stops listening on request", async () => {
    const unlisten = vi.fn();
    listen.mockImplementation((_name: string, callback: (event: { payload: unknown }) => void) => {
      callback({ payload: { latestVersion: "2.0.0" } });
      return Promise.resolve(unlisten);
    });
    const handler = vi.fn();
    const stop = await listenUpdatesAvailable(handler);
    expect(listen).toHaveBeenCalledWith(UPDATES_AVAILABLE_EVENT, expect.any(Function));
    expect(handler).toHaveBeenCalledWith({ latestVersion: "2.0.0" });
    stop();
    expect(unlisten).toHaveBeenCalled();
  });

  it("is a no-op outside the app", async () => {
    inTauri = false;
    const stop = await listenUpdatesAvailable(vi.fn());
    expect(listen).not.toHaveBeenCalled();
    expect(() => stop()).not.toThrow();
  });
});
