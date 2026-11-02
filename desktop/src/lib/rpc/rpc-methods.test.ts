import { describe, expect, it } from "vitest";
import type * as contract from "@/lib/api/types.gen";
import type { RpcMethod } from "./rpc-methods";

// The wire names the helper declares (`Method*` constants in the generated types).
type ContractMethods = (typeof contract)[Extract<keyof typeof contract, `Method${string}`>];

// Both directions must hold: a method added to the helper without an entry in
// `RpcMethods`, or an entry the helper does not have, fails `pnpm typecheck`.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;
const everyMethodIsTyped: Same<ContractMethods, RpcMethod> = true;

describe("RpcMethods", () => {
  it("covers every method of the generated contract", () => {
    expect(everyMethodIsTyped).toBe(true);
  });
});
