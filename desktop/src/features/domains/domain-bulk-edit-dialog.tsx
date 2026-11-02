import { LoaderCircle, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { firstInvalidEntry, parseDomainLines } from "./entry-input";
import { FindableTextEditor } from "./findable-text-editor";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** The list as it is when the dialog opens. */
  entries: readonly string[];
  onSave: (patterns: string[]) => Promise<boolean>;
}

/** Edits a whole list as text, one entry per line, and saves it in one go. Saving empty text clears the list. */
export function DomainBulkEditDialog({ open, onOpenChange, title, entries, onSave }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <BulkEditForm title={title} initialText={entries.join("\n")} onSave={onSave} onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  );
}

interface FormProps {
  title: string;
  initialText: string;
  onSave: (patterns: string[]) => Promise<boolean>;
  onClose: () => void;
}

/** Mounted only while the dialog is open, so each opening starts from the list's current text. */
function BulkEditForm({ title, initialText, onSave, onClose }: FormProps) {
  const [text, setText] = useState(initialText);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string>();

  const entries = parseDomainLines(text);
  const invalid = firstInvalidEntry(entries);

  async function save() {
    setIsSaving(true);
    setError(undefined);
    try {
      if (await onSave(entries)) onClose();
      else setError("Could not save; the list is unchanged.");
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>
          One entry per line. Lines starting with # are ignored. Leave it empty to clear the list.
        </DialogDescription>
      </DialogHeader>
      <FindableTextEditor value={text} onChange={setText} disabled={isSaving} />
      {error ?? invalid ? (
        <p role="alert" className="flex items-center gap-1.5 text-xs text-destructive">
          <TriangleAlert aria-hidden className="size-3.5 shrink-0" />
          {error ?? invalid}
        </p>
      ) : null}
      <DialogFooter className="items-center">
        <span className="mr-auto text-xs text-muted-foreground">
          {entries.length} {entries.length === 1 ? "entry" : "entries"}
        </span>
        {isSaving ? <LoaderCircle aria-label="Saving" className="size-4 animate-spin text-muted-foreground" /> : null}
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button disabled={isSaving || invalid !== undefined || text === initialText} onClick={() => void save()}>
          Save
        </Button>
      </DialogFooter>
    </>
  );
}
