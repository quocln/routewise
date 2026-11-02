import { toRpcError } from "@/lib/rpc/rpc-error";

/** JSON-RPC "method not found": a helper that predates the method. */
const METHOD_NOT_FOUND = -32601;

/** What to tell the user about a failed call to a method older helpers lack. */
export function featureErrorMessage(error: unknown): string {
  const rpcError = toRpcError(error);
  if (rpcError.kind === "remote" && rpcError.code === METHOD_NOT_FOUND) {
    return "Reinstall the helper to use this feature.";
  }
  return rpcError.message;
}
