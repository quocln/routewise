"use client";

import { useRef, type ReactNode } from "react";

/**
 * A hidden file input for choosing a WireGuard `.conf`. `open(onPick)` shows
 * the system file chooser and hands the chosen file to `onPick`; the file is
 * not read here. Render `input` once.
 */
export function useWireGuardFilePicker(): { open: (onPick: (file: File) => void) => void; input: ReactNode } {
  const inputRef = useRef<HTMLInputElement>(null);
  const onPickRef = useRef<((file: File) => void) | null>(null);

  const input = (
    <input
      ref={inputRef}
      type="file"
      accept=".conf,text/plain"
      hidden
      aria-label="Choose a WireGuard .conf file"
      data-testid="wireguard-file-input"
      onChange={(event) => {
        const file = event.target.files?.[0];
        // Cleared so choosing the same file again still fires a change.
        event.target.value = "";
        if (file) onPickRef.current?.(file);
      }}
    />
  );

  return {
    open: (onPick) => {
      onPickRef.current = onPick;
      inputRef.current?.click();
    },
    input,
  };
}
