import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { rpc } from "@/lib/rpc/rpc-client";
import type { RpcError } from "@/lib/rpc/rpc-error";
import { planAdd } from "./entry-input";
import { domainListKey, domainListQuery } from "./use-domain-lists";

export type AddResult =
  | { kind: "added"; count: number; skipped: number }
  | { kind: "invalid"; message: string }
  | { kind: "duplicates" }
  | { kind: "nothing" }
  | { kind: "failed" };

export interface DomainListEntries {
  entries: string[];
  isLoading: boolean;
  /** True while an add, remove, or bulk save is in flight. */
  isSaving: boolean;
  /** The helper's error from the last load or change, shown below the list. */
  error: string | undefined;
  addEntries: (input: string) => Promise<AddResult>;
  removeEntries: (patterns: ReadonlySet<string>) => Promise<boolean>;
  /** Replaces the whole list; an empty array clears it. */
  setEntries: (patterns: readonly string[]) => Promise<boolean>;
}

/** The current helper list of `vpn`, so a change made elsewhere meanwhile is kept. */
async function currentPatterns(vpn: string): Promise<string[]> {
  return (await rpc("domains.list", { vpn })).map((d) => d.pattern);
}

/**
 * The entries of one list and the changes to it. Every change is applied to
 * the helper at once and the list is reloaded; there is no unsaved state
 * outside the bulk text editor.
 */
export function useDomainListEntries(vpn: string): DomainListEntries {
  const queryClient = useQueryClient();
  const query = useQuery<string[], RpcError>(domainListQuery(vpn));
  const [mutationError, setMutationError] = useState<{ vpn: string; message: string }>();
  const { mutateAsync, isPending } = useMutation<void, RpcError, () => Promise<void>>({
    mutationFn: (change) => change(),
  });

  const entries = query.data ?? EMPTY;

  /** Runs one change to `vpn`'s list and reloads it. */
  const mutate = useCallback(
    async (change: () => Promise<void>): Promise<boolean> => {
      setMutationError(undefined);
      try {
        await mutateAsync(change);
      } catch (error) {
        setMutationError({ vpn, message: error instanceof Error ? error.message : String(error) });
        return false;
      }
      await queryClient.invalidateQueries({ queryKey: domainListKey(vpn) });
      return true;
    },
    [mutateAsync, queryClient, vpn],
  );

  const addEntries = useCallback(
    async (input: string): Promise<AddResult> => {
      const plan = planAdd(input, entries);
      switch (plan.kind) {
        case "nothing":
          return { kind: "nothing" };
        case "invalid":
          return { kind: "invalid", message: plan.message };
        case "duplicates":
          return { kind: "duplicates" };
        case "add": {
          const { fresh } = plan;
          const ok = await mutate(async () => {
            if (fresh.length === 1) {
              await rpc("domains.add", { pattern: fresh[0], vpn });
            } else {
              const current = await currentPatterns(vpn);
              await rpc("domains.set", { patterns: [...current, ...fresh], vpn });
            }
          });
          return ok ? { kind: "added", count: fresh.length, skipped: plan.skipped } : { kind: "failed" };
        }
      }
    },
    [entries, mutate, vpn],
  );

  const removeEntries = useCallback(
    async (patterns: ReadonlySet<string>): Promise<boolean> => {
      if (patterns.size === 0) return true;
      return mutate(async () => {
        if (patterns.size === 1) {
          const [only] = patterns;
          await rpc("domains.remove", { pattern: only, vpn });
        } else {
          const current = await currentPatterns(vpn);
          await rpc("domains.set", { patterns: current.filter((p) => !patterns.has(p)), vpn });
        }
      });
    },
    [mutate, vpn],
  );

  const setEntries = useCallback(
    (patterns: readonly string[]) =>
      mutate(async () => {
        await rpc("domains.set", { patterns: [...patterns], vpn });
      }),
    [mutate, vpn],
  );

  const error = mutationError?.vpn === vpn ? mutationError.message : query.error?.message;

  return {
    entries,
    isLoading: query.isPending,
    isSaving: isPending,
    error,
    addEntries,
    removeEntries,
    setEntries,
  };
}

const EMPTY: string[] = [];
