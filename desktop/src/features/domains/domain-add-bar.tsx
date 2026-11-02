import { Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { AddResult } from "./use-domain-list-entries";

/** What the last add attempt reported. */
export interface AddFeedback {
  text: string;
  isError: boolean;
}

/** Turns an add result into the line shown under the field; the field clears when `clear` is true. */
export function feedbackFor(result: AddResult): { feedback: AddFeedback | undefined; clear: boolean } {
  switch (result.kind) {
    case "added":
      return {
        clear: true,
        feedback: {
          isError: false,
          text:
            result.skipped > 0
              ? `Added ${result.count}; ${result.skipped} already in the list.`
              : result.count === 1
                ? "Added."
                : `Added ${result.count} entries.`,
        },
      };
    case "invalid":
      return { clear: false, feedback: { text: result.message, isError: true } };
    case "duplicates":
      return { clear: false, feedback: { text: "Already in this list.", isError: true } };
    case "nothing":
      return { clear: false, feedback: undefined };
    case "failed":
      // The pane shows the helper's error below the list.
      return { clear: false, feedback: undefined };
  }
}

interface Props {
  canEdit: boolean;
  feedback: AddFeedback | undefined;
  onFeedback: (feedback: AddFeedback | undefined) => void;
  onAdd: (input: string) => Promise<AddResult>;
}

/** The add field: domains, wildcards, IPs, and CIDRs, several at once. */
export function DomainAddBar({ canEdit, feedback, onFeedback, onAdd }: Props) {
  const [value, setValue] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canEdit || value.trim() === "") return;
    const outcome = feedbackFor(await onAdd(value));
    if (outcome.clear) setValue("");
    onFeedback(outcome.feedback);
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-1">
      <div className="flex gap-1.5">
        <Input
          aria-label="Add entries"
          value={value}
          placeholder="Add example.com, *.example.com, 10.20.30.40, or 10.20.0.0/16"
          className="font-mono"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => {
            setValue(event.target.value);
            if (feedback?.isError) onFeedback(undefined);
          }}
        />
        <Button type="submit" disabled={!canEdit || value.trim() === ""}>
          <Plus data-icon="inline-start" />
          Add
        </Button>
      </div>
      <p className={cn("text-xs", feedback?.isError ? "text-destructive" : "text-muted-foreground")}>
        {feedback?.text ??
          'Paste several at once, separated by commas, spaces, or new lines. "*.example.com" matches api.example.com, not example.com.'}
      </p>
    </form>
  );
}
