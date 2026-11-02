import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri: () => true }));

const { ErrorBoundary } = await import("./error-boundary");

function Broken(): never {
  throw new Error("render failed");
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    invoke.mockReset().mockResolvedValue(null);
    // React logs a caught render error to the console; keep the output clean.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders its children when nothing fails", () => {
    render(
      <ErrorBoundary>
        <p>all good</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("all good")).toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("reports a render error and shows a way back", () => {
    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong");
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();

    expect(invoke).toHaveBeenCalledTimes(1);
    const [command, args] = invoke.mock.calls[0] as [string, { report: Record<string, string> }];
    expect(command).toBe("report_ui_error");
    expect(args.report.kind).toBe("render");
    expect(args.report.message).toBe("Error: render failed");
    expect(args.report.componentStack).toContain("Broken");
  });
});
