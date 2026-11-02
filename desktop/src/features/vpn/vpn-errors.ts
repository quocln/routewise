import { RpcError } from "@/lib/rpc/rpc-error";

/** JSON-RPC "method not found", which an older helper returns for newer methods. */
const METHOD_NOT_FOUND = -32601;

/**
 * What to tell the user about a failed call to a method older helpers lack.
 * Never includes request params: they may hold a key or a config.
 */
export function helperFeatureErrorMessage(error: unknown): string {
  if (error instanceof RpcError) {
    return error.code === METHOD_NOT_FOUND ? "Reinstall the helper to use this feature." : error.message;
  }
  return error instanceof Error ? error.message : "Unknown error";
}
