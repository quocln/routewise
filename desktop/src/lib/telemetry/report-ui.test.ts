import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
const isTauri = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri }));

const { logUi, reportUiError } = await import("./report-ui");

describe("report-ui", () => {
  beforeEach(() => {
    invoke.mockReset().mockResolvedValue(null);
    isTauri.mockReset().mockReturnValue(true);
  });

  it("sends an error report to the core", () => {
    reportUiError({ kind: "render", message: "boom", componentStack: "in App" });
    expect(invoke).toHaveBeenCalledWith("report_ui_error", {
      report: { kind: "render", message: "boom", componentStack: "in App" },
    });
  });

  it("sends a log line to the core", () => {
    logUi("warn", "slow");
    expect(invoke).toHaveBeenCalledWith("log_ui", { entry: { level: "warn", message: "slow" } });
  });

  it("does nothing outside the app", () => {
    isTauri.mockReturnValue(false);
    reportUiError({ kind: "error", message: "x" });
    logUi("error", "x");
    expect(invoke).not.toHaveBeenCalled();
  });

  it("swallows a failing core call", async () => {
    invoke.mockImplementation(() => Promise.reject(new Error("no core")));
    expect(() => reportUiError({ kind: "error", message: "x" })).not.toThrow();
    expect(() => logUi("error", "x")).not.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
});
