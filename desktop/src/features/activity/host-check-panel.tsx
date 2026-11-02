"use client";

import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { HostAddress } from "@/lib/api/types.gen";
import { rpc } from "@/lib/rpc/rpc-client";
import { featureErrorMessage } from "./helper-feature-error";

/** Interface, gateway, routedFor, and note, joined by what is present. */
export function addressDetail(address: HostAddress): string {
  return [
    address.interface,
    address.gateway ? `via ${address.gateway}` : undefined,
    address.routedFor ? `for ${address.routedFor}` : undefined,
    address.note,
  ]
    .filter((part): part is string => Boolean(part))
    .join(" · ");
}

/** Text field and result panel for routes.check: where traffic to a host goes right now. */
export function HostCheckPanel() {
  const [host, setHost] = useState("");
  const check = useMutation({ mutationFn: (value: string) => rpc("routes.check", { host: value }) });
  const trimmed = host.trim();

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (trimmed !== "" && !check.isPending) check.mutate(trimmed);
  };

  const result = check.data;
  return (
    <div className="flex flex-col gap-2 px-4 pb-2">
      <form onSubmit={submit} className="flex items-center gap-2">
        <Input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="Check a host, IP, or URL"
          aria-label="Host to check"
          className="max-w-md"
        />
        <Button type="submit" size="sm" disabled={check.isPending || trimmed === ""}>
          {check.isPending ? "Checking..." : "Check"}
        </Button>
      </form>
      {check.error ? (
        <p role="alert" className="text-xs text-destructive">
          {featureErrorMessage(check.error)}
        </p>
      ) : null}
      {result ? (
        <div className="flex flex-col gap-1.5 rounded-md bg-muted/50 p-2" data-testid="host-check-result">
          <span className="font-mono text-sm font-semibold">{result.host}</span>
          <span className="text-xs text-muted-foreground">
            {result.matchedPatterns?.length
              ? `Matches: ${result.matchedPatterns.join(", ")}`
              : "no configured domain"}
          </span>
          {result.addresses.map((address) => (
            <div key={address.ip} className="flex items-baseline gap-2">
              <Badge variant={address.verdict === "vpn" ? "default" : "secondary"}>
                {address.verdict === "vpn" ? "VPN" : "DIRECT"}
              </Badge>
              <span className="font-mono text-sm">{address.ip}</span>
              <span className="truncate text-xs text-muted-foreground">{addressDetail(address)}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
