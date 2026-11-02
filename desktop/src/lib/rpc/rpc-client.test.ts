import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
const isTauri = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri }));

const { rpc } = await import("./rpc-client");
const { RpcError } = await import("./rpc-error");

describe("rpc", () => {
  beforeEach(() => {
    invoke.mockReset();
    isTauri.mockReset().mockReturnValue(true);
  });

  it("invokes the core with the method and no params", async () => {
    invoke.mockResolvedValue({ running: true });
    await expect(rpc("status.get")).resolves.toEqual({ running: true });
    expect(invoke).toHaveBeenCalledWith("rpc", { method: "status.get", params: undefined });
  });

  it("passes params through", async () => {
    invoke.mockResolvedValue({ success: true });
    await rpc("domains.add", { pattern: "example.com" });
    expect(invoke).toHaveBeenCalledWith("rpc", { method: "domains.add", params: { pattern: "example.com" } });
  });

  it("rejects with a typed RpcError", async () => {
    invoke.mockImplementation(() => Promise.reject({ kind: "remote", code: -32602, message: "Invalid params" }));
    const error = await rpc("routes.check", { host: "" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RpcError);
    expect(error).toMatchObject({ kind: "remote", code: -32602 });
  });

  it("is unavailable outside the app", async () => {
    isTauri.mockReturnValue(false);
    await expect(rpc("status.get")).rejects.toMatchObject({ kind: "unavailable" });
    expect(invoke).not.toHaveBeenCalled();
  });
});
