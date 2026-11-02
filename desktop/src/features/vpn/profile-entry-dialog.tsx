"use client";

import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { accessKeyProblem, normalizeAccessKey } from "./vpn-format";
import { helperFeatureErrorMessage } from "./vpn-errors";

export interface ProfileEntryDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  confirmLabel: string;
  explanation?: string;
  /** Null hides the name field. */
  initialName: string | null;
  askKey: boolean;
  /** Receives the trimmed name (empty when not asked) and the key (empty when not asked). */
  submit: (name: string, key: string) => Promise<void>;
}

type FormProps = Omit<ProfileEntryDialogProps, "open" | "title" | "explanation">;

/**
 * The form. It is mounted only while the dialog is open, so the key typed into
 * it lives in this component's state alone and is gone when the dialog closes.
 */
function EntryForm({ onClose, confirmLabel, initialName, askKey, submit }: FormProps) {
  const [name, setName] = useState(initialName ?? "");
  const [key, setKey] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmedName = name.trim();
  const canSubmit = !sending && !(initialName !== null && trimmedName === "") && !(askKey && key === "");

  async function send(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    if (askKey) {
      const problem = accessKeyProblem(key);
      if (problem) {
        setError(problem);
        return;
      }
    }
    const sentKey = askKey ? normalizeAccessKey(key) : "";
    setSending(true);
    setError(null);
    try {
      await submit(trimmedName, sentKey);
      onClose();
    } catch (failure) {
      setError(helperFeatureErrorMessage(failure));
    } finally {
      // Whether or not it worked, the key is not kept.
      setKey("");
      setSending(false);
    }
  }

  return (
    <form onSubmit={send} className="grid gap-3">
      {initialName !== null ? (
        <div className="grid gap-1.5">
          <Label htmlFor="profile-name">Name</Label>
          <Input id="profile-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
        </div>
      ) : null}
      {askKey ? (
        <div className="grid gap-1.5">
          <Label htmlFor="profile-key">Access key</Label>
          <Input
            id="profile-key"
            type="password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="ss:// or ssconf:// access key"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" disabled={!canSubmit}>
          {sending ? "Working…" : confirmLabel}
        </Button>
      </DialogFooter>
    </form>
  );
}

/** A small dialog for a profile name and/or an Outline access key. */
export function ProfileEntryDialog({ open, title, explanation, ...form }: ProfileEntryDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(next) => !next && form.onClose()}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {explanation ? <DialogDescription>{explanation}</DialogDescription> : null}
        </DialogHeader>
        <EntryForm {...form} />
      </DialogContent>
    </Dialog>
  );
}
