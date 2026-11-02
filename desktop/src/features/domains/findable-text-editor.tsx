import { ChevronDown, ChevronUp, X } from "lucide-react";
import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { findMatches, nextMatch, previousMatch } from "./find-matches";

interface Props {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}

/**
 * A plain-text editor with a find bar: Cmd/Ctrl+F opens it, Enter or Cmd+G
 * jumps to the next match, Shift+Enter or Shift+Cmd+G to the previous one.
 */
export function FindableTextEditor({ value, onChange, disabled }: Props) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const findRef = useRef<HTMLInputElement>(null);
  const [finding, setFinding] = useState(false);
  const [query, setQuery] = useState("");

  const matches = findMatches(value, query);

  /** Selects the match starting at `start` in the editor and scrolls it into view. */
  function reveal(start: number | undefined) {
    const area = textareaRef.current;
    if (!area || start === undefined) return;
    area.focus();
    area.setSelectionRange(start, start + query.length);
    // The editor does not wrap, so a line is one row of text.
    const line = value.slice(0, start).split("\n").length - 1;
    const lineHeight = parseFloat(getComputedStyle(area).lineHeight) || 20;
    area.scrollTop = Math.max(0, line * lineHeight - area.clientHeight / 2);
  }

  function step(direction: "next" | "previous") {
    const area = textareaRef.current;
    const caret = direction === "next" ? (area?.selectionEnd ?? 0) : (area?.selectionStart ?? 0);
    reveal((direction === "next" ? nextMatch : previousMatch)(matches, caret));
  }

  function openFind() {
    setFinding(true);
    requestAnimationFrame(() => findRef.current?.select());
  }

  function onEditorKeyDown(event: React.KeyboardEvent) {
    if (!(event.metaKey || event.ctrlKey)) return;
    const key = event.key.toLowerCase();
    if (key === "f") {
      event.preventDefault();
      openFind();
    } else if (key === "g" && finding) {
      event.preventDefault();
      step(event.shiftKey ? "previous" : "next");
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      {finding ? (
        <div role="search" className="flex items-center gap-1">
          <Input
            ref={findRef}
            aria-label="Find"
            placeholder="Find"
            value={query}
            className="h-7 font-mono"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                step(event.shiftKey ? "previous" : "next");
              } else if (event.key === "Escape") {
                // Closes the find bar, not the dialog around it.
                event.stopPropagation();
                setFinding(false);
                textareaRef.current?.focus();
              }
            }}
          />
          <span className="w-20 text-center text-xs text-muted-foreground" aria-live="polite">
            {query === "" ? "" : matches.length === 0 ? "No matches" : `${matches.length} found`}
          </span>
          <Button variant="ghost" size="icon-xs" aria-label="Previous match" disabled={matches.length === 0} onClick={() => step("previous")}>
            <ChevronUp />
          </Button>
          <Button variant="ghost" size="icon-xs" aria-label="Next match" disabled={matches.length === 0} onClick={() => step("next")}>
            <ChevronDown />
          </Button>
          <Button variant="ghost" size="icon-xs" aria-label="Close find" onClick={() => setFinding(false)}>
            <X />
          </Button>
        </div>
      ) : null}
      <Textarea
        ref={textareaRef}
        aria-label="Entries as text"
        value={value}
        disabled={disabled}
        wrap="off"
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={onEditorKeyDown}
        className="h-64 resize-none overflow-auto font-mono field-sizing-fixed"
      />
    </div>
  );
}
