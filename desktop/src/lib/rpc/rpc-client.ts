import { invoke, isTauri } from "@tauri-apps/api/core";
import { RpcError, toRpcError } from "./rpc-error";
import type { RpcArgs, RpcMethod, RpcResult } from "./rpc-methods";

/**
 * Calls a helper method through the app's Rust core and returns its result.
 * Rejects with an `RpcError`.
 */
export async function rpc<M extends RpcMethod>(method: M, ...args: RpcArgs<M>): Promise<RpcResult<M>> {
  if (!isTauri()) {
    throw new RpcError({ kind: "unavailable", message: "not running inside the RouteWise app" });
  }
  try {
    return await invoke<RpcResult<M>>("rpc", { method, params: args[0] });
  } catch (error) {
    throw toRpcError(error);
  }
}
