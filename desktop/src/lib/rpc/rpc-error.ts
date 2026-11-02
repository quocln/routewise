/** Mirrors the Rust core's `RpcError` (`src-tauri/src/rpc/error.rs`). */
export type RpcErrorPayload =
  | { kind: "unavailable"; message: string }
  | { kind: "timeout"; seconds: number }
  | { kind: "protocol"; message: string }
  | { kind: "remote"; code: number; message: string }
  | { kind: "invalidRequest"; message: string };

export type RpcErrorKind = RpcErrorPayload["kind"];

/** An error from the helper or from reaching it. */
export class RpcError extends Error {
  readonly kind: RpcErrorKind;
  readonly code?: number;

  constructor(payload: RpcErrorPayload) {
    super(describe(payload));
    this.name = "RpcError";
    this.kind = payload.kind;
    if (payload.kind === "remote") this.code = payload.code;
  }

  /** True when the helper could not be reached at all. */
  get isUnavailable(): boolean {
    return this.kind === "unavailable";
  }
}

function describe(payload: RpcErrorPayload): string {
  switch (payload.kind) {
    case "timeout":
      return `The helper did not answer within ${payload.seconds} s`;
    case "unavailable":
      return `The helper is not reachable: ${payload.message}`;
    case "protocol":
      return `The helper sent an invalid response: ${payload.message}`;
    case "invalidRequest":
      return `Invalid request: ${payload.message}`;
    case "remote":
      return payload.message;
  }
}

const KINDS: readonly string[] = ["unavailable", "timeout", "protocol", "remote", "invalidRequest"];

function isPayload(value: unknown): value is RpcErrorPayload {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    typeof value.kind === "string" &&
    KINDS.includes(value.kind)
  );
}

/** Turns whatever a Tauri command rejected with into an `RpcError`. */
export function toRpcError(value: unknown): RpcError {
  if (value instanceof RpcError) return value;
  if (isPayload(value)) return new RpcError(value);
  const message = value instanceof Error ? value.message : String(value);
  return new RpcError({ kind: "unavailable", message });
}
