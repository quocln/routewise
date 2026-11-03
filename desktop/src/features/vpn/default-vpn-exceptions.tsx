"use client";

import { useState } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * The domains, wildcards, IPs and networks that go direct instead of through the
 * default VPN. The helper decides what is valid, so an entry it refuses stays in the
 * box with its reason beside it, and nothing here claims a route exists.
 */
export function DefaultVPNExceptions({
  entries,
  disabled,
  onChange,
}: {
  entries: string[];
  disabled: boolean;
  /** Saves the whole list; rejects with the helper's reason. */
  onChange: (next: string[]) => Promise<unknown>;
}) {
  const [draft, setDraft] = useState("");

  const add = async () => {
    const entry = draft.trim();
    if (!entry) return;
    if (!entries.includes(entry)) {
      try {
        await onChange([...entries, entry]);
      } catch {
        return; // The section shows why, and the entry stays to be corrected.
      }
    }
    setDraft("");
  };

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2 text-sm">
      <span id="default-vpn-exceptions-label">Except these, which go direct</span>
      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          void add();
        }}
      >
        <Input
          aria-labelledby="default-vpn-exceptions-label"
          placeholder="bank.example.com, *.example.com, 203.0.113.9, 198.51.100.0/24"
          value={draft}
          disabled={disabled}
          onChange={(event) => setDraft(event.target.value)}
        />
        <Button type="submit" variant="outline" disabled={disabled || !draft.trim()}>
          Add
        </Button>
      </form>
      {entries.length > 0 ? (
        <ul className="grid grid-cols-[minmax(0,1fr)] gap-1" aria-label="Exceptions">
          {entries.map((entry) => (
            <li key={entry} className="flex items-center justify-between gap-2 text-xs">
              <span className="min-w-0 truncate font-mono">{entry}</span>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove ${entry}`}
                disabled={disabled}
                onClick={() => void onChange(entries.filter((other) => other !== entry)).catch(() => undefined)}
              >
                <X aria-hidden className="size-3.5" />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
