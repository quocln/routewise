"use client";

import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { helperFeatureErrorMessage } from "./vpn-errors";
import { isLocalHost, proxyAddress, proxyProblem, type ProxyKind } from "./vpn-format";

const DEFAULT_PORT: Record<ProxyKind, string> = { socks5: "1080", http: "8080" };

const WHAT_IT_DOES_NOT_PROTECT: Record<ProxyKind, string> = {
  socks5:
    "SOCKS5 does not encrypt anything. The proxy, and anyone on the network to it, can read traffic that is not already encrypted, such as plain HTTP, and the password itself.",
  http: "The connection to an HTTP proxy is not encrypted, so anyone on the network to it can read the password and the sites you connect to. It carries only TCP, and many proxies allow only HTTPS. It must support CONNECT.",
};

interface Props {
  open: boolean;
  onClose: () => void;
  proxy: ProxyKind;
  title: string;
  confirmLabel: string;
  askName: boolean;
  /** Receives the trimmed name (empty when not asked) and the proxy's address. */
  submit: (name: string, address: string) => Promise<void>;
}

/**
 * The form. It is mounted only while the dialog is open, so the password typed into
 * it lives in this component's state alone and is gone when the dialog closes.
 */
function EntryForm({ onClose, proxy, confirmLabel, askName, submit }: Omit<Props, "open" | "title">) {
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(DEFAULT_PORT[proxy]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmedName = name.trim();
  const canSubmit = !sending && !(askName && trimmedName === "") && host.trim() !== "";
  // Advice, not a refusal: the user may know this proxy is theirs.
  const openOnTheInternet = host.trim() !== "" && username === "" && !isLocalHost(host);

  async function send(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    const fields = { host, port, username, password };
    const problem = proxyProblem(fields);
    if (problem) {
      setError(problem);
      return;
    }
    setSending(true);
    setError(null);
    try {
      await submit(trimmedName, proxyAddress(proxy, fields));
      onClose();
    } catch (failure) {
      setError(helperFeatureErrorMessage(failure));
    } finally {
      // Whether or not it worked, the password is not kept.
      setPassword("");
      setSending(false);
    }
  }

  return (
    <form onSubmit={send} className="grid gap-3">
      {askName ? (
        <div className="grid gap-1.5">
          <Label htmlFor="proxy-name">Name</Label>
          <Input id="proxy-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
        </div>
      ) : null}
      <div className="grid grid-cols-[minmax(0,1fr)_6rem] gap-2">
        <div className="grid gap-1.5">
          <Label htmlFor="proxy-host">Host</Label>
          <Input
            id="proxy-host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="127.0.0.1 or proxy.example.com"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="proxy-port">Port</Label>
          <Input
            id="proxy-port"
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            autoComplete="off"
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="grid gap-1.5">
          <Label htmlFor="proxy-username">Username (optional)</Label>
          <Input
            id="proxy-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="proxy-password">Password (optional)</Label>
          <Input
            id="proxy-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
        </div>
      </div>
      {openOnTheInternet ? (
        <p className="text-xs text-orange-600 dark:text-orange-400">
          A proxy on the Internet with no password is open to anyone, and whoever runs it can read traffic that is not
          already encrypted. Use one only if you trust it.
        </p>
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

/** A dialog for a proxy, which says what the protocol does not protect. */
export function ProxyEntryDialog({ open, title, ...form }: Props) {
  return (
    <Dialog open={open} onOpenChange={(next) => !next && form.onClose()}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{WHAT_IT_DOES_NOT_PROTECT[form.proxy]}</DialogDescription>
        </DialogHeader>
        <EntryForm {...form} />
      </DialogContent>
    </Dialog>
  );
}
