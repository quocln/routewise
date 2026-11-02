import { describe, expect, it } from "vitest";
import { RpcError, toRpcError } from "./rpc-error";

describe("toRpcError", () => {
  it("rebuilds the Rust core's error payloads", () => {
    const error = toRpcError({ kind: "remote", code: -32001, message: "unauthorized" });
    expect(error).toBeInstanceOf(RpcError);
    expect(error.kind).toBe("remote");
    expect(error.code).toBe(-32001);
    expect(error.message).toBe("unauthorized");
  });

  it("flags an unreachable helper", () => {
    expect(toRpcError({ kind: "unavailable", message: "No such file" }).isUnavailable).toBe(true);
    expect(toRpcError({ kind: "timeout", seconds: 30 }).isUnavailable).toBe(false);
  });

  it("wraps anything else as unavailable", () => {
    expect(toRpcError(new Error("boom")).kind).toBe("unavailable");
    expect(toRpcError("plain string").message).toContain("plain string");
  });

  it("returns an RpcError unchanged", () => {
    const original = new RpcError({ kind: "protocol", message: "bad" });
    expect(toRpcError(original)).toBe(original);
  });
});
