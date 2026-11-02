import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
const isTauri = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri }));

const { installErrorForwarding } = await import("./install-error-forwarding");

/** A window-like target so the test never touches jsdom's global listeners. */
function fakeWindow() {
  const target = new EventTarget();
  return target as unknown as Window;
}

function rejection(reason: unknown): Event {
  const event = new Event("unhandledrejection");
  Object.assign(event, { reason });
  return event;
}

function scriptError(message: string, error?: unknown): Event {
  const event = new Event("error");
  Object.assign(event, { message, error });
  return event;
}

describe("installErrorForwarding", () => {
  let target: Window;
  let remove: () => void;

  beforeEach(() => {
    invoke.mockReset().mockResolvedValue(null);
    isTauri.mockReset().mockReturnValue(true);
    target = fakeWindow();
    remove = installErrorForwarding(target);
  });
  afterEach(() => remove());

  it("forwards an uncaught error with its stack", () => {
    const error = new TypeError("x is undefined");
    target.dispatchEvent(scriptError("Uncaught TypeError: x is undefined", error));
    expect(invoke).toHaveBeenCalledWith("report_ui_error", {
      report: { kind: "error", message: "Uncaught TypeError: x is undefined", stack: error.stack },
    });
  });

  it("forwards an unhandled rejection of an Error", () => {
    const error = new RangeError("too far");
    target.dispatchEvent(rejection(error));
    expect(invoke).toHaveBeenCalledWith("report_ui_error", {
      report: { kind: "unhandledrejection", message: "RangeError: too far", stack: error.stack },
    });
  });

  it("describes a rejection that is not an Error", () => {
    target.dispatchEvent(rejection("plain text"));
    target.dispatchEvent(rejection({ code: 7 }));
    const messages = invoke.mock.calls.map(([, args]) => (args as { report: { message: string } }).report.message);
    expect(messages).toEqual(["plain text", '{"code":7}']);
  });

  it("ignores the benign ResizeObserver notice", () => {
    target.dispatchEvent(scriptError("ResizeObserver loop completed with undelivered notifications."));
    expect(invoke).not.toHaveBeenCalled();
  });

  it("stops forwarding once removed", () => {
    remove();
    target.dispatchEvent(scriptError("late"));
    expect(invoke).not.toHaveBeenCalled();
  });

  it("installs nothing outside the app", () => {
    isTauri.mockReturnValue(false);
    const outside = fakeWindow();
    const off = installErrorForwarding(outside);
    outside.dispatchEvent(scriptError("ignored"));
    off();
    expect(invoke).not.toHaveBeenCalled();
  });
});
