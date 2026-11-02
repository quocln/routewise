"use client";

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import { rpc } from "@/lib/rpc/rpc-client";
import { CleanDnsDialog } from "./clean-dns-dialog";
import { Note, Outcome, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";

const routeCount = (n: number) => (n === 1 ? "1 learned route" : `${n} learned routes`);

/** Actions that clear what RouteWise and the system remember about DNS. */
export function DnsSection() {
  const available = useHelperAvailable();
  const [confirmClean, setConfirmClean] = useState(false);
  const clearCache = useMutation({ mutationFn: () => rpc("dns.clearCache") });
  const clean = useMutation({ mutationFn: () => rpc("dns.clean") });
  const busy = clearCache.isPending || clean.isPending;

  return (
    <SettingsSection title="DNS">
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={!available || busy}
          onClick={() => {
            clean.reset();
            clearCache.mutate();
          }}>
          Clear DNS Cache
        </Button>
        <Button variant="outline" size="sm" disabled={!available || busy} onClick={() => setConfirmClean(true)}>
          Clean DNS
        </Button>
      </div>
      {!available ? <Note tone="warning">Unavailable until the app reconnects to the RouteWise helper.</Note> : null}
      <Note>
        Clear DNS Cache empties the cache of RouteWise and of the system, and leaves routes alone; new addresses of
        exact domains are picked up at the next refresh. Clean DNS also removes the routes learned from wildcard
        lookups and refreshes at once, which can drop connections open over those routes.
      </Note>
      {clearCache.isSuccess ? <Outcome kind="ok">DNS cache cleared.</Outcome> : null}
      {clearCache.isError ? (
        <Outcome kind="error">{`Could not clear the DNS cache: ${featureErrorMessage(clearCache.error)}`}</Outcome>
      ) : null}
      {clean.isSuccess ? (
        <Outcome kind="ok">{`DNS cleaned. Removed ${routeCount(clean.data.routesRemoved)}.`}</Outcome>
      ) : null}
      {clean.isError ? <Outcome kind="error">{`Could not clean DNS: ${featureErrorMessage(clean.error)}`}</Outcome> : null}
      <CleanDnsDialog
        open={confirmClean}
        onOpenChange={setConfirmClean}
        onConfirm={() => {
          clearCache.reset();
          clean.mutate();
        }}
      />
    </SettingsSection>
  );
}
