import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readStored, resetWrittenForTests, usePersistedState, writeStored } from "./use-persisted-state";

const isString = (value: unknown): value is string => typeof value === "string";

afterEach(() => {
  window.localStorage.clear();
  resetWrittenForTests();
  vi.restoreAllMocks();
});

describe("usePersistedState", () => {
  it("starts from the stored value and stores changes", () => {
    writeStored("tab", "domains");
    const { result } = renderHook(() => usePersistedState("tab", "vpn", isString));
    expect(result.current[0]).toBe("domains");
    act(() => result.current[1]("activity"));
    expect(readStored("tab", isString)).toBe("activity");
  });

  it("falls back when the stored value is invalid or unreadable", () => {
    window.localStorage.setItem("routewise.tab", "{not json");
    const { result } = renderHook(() => usePersistedState("tab", "vpn", isString));
    expect(result.current[0]).toBe("vpn");
    writeStored("tab", 42);
    expect(readStored("tab", isString)).toBeUndefined();
  });

  it("keeps working when storage throws", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    const { result } = renderHook(() => usePersistedState("tab", "vpn", isString));
    act(() => result.current[1]("settings"));
    expect(result.current[0]).toBe("settings");
  });
});
