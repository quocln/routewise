"use client";

import { useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import type { HelperServiceStatus } from "@/lib/native/native-commands";
import { useStatus } from "@/lib/rpc/queries";
import { cn } from "@/lib/utils";
import { Note, Outcome, SettingsSection } from "./settings-section";
import { useHelperService } from "./use-helper-service";

/**
 * How the helper looks from its status answer, and from the OS service when the
 * helper does not answer: a service that is missing or stopped says so, one that
 * runs but is silent is not reachable.
 */
export function helperState(
  status: { running: boolean; degraded?: boolean } | undefined,
  failed: boolean,
  service?: HelperServiceStatus,
): { label: string; dot: string } {
  if (failed) {
    if (service && !service.installed) return { label: "Not installed", dot: "bg-muted-foreground" };
    if (service && !service.running) return { label: "Stopped", dot: "bg-red-500" };
    return { label: "Not reachable", dot: "bg-red-500" };
  }
  if (!status) return { label: "Checking...", dot: "bg-muted-foreground" };
  if (!status.running) return { label: "Stopped", dot: "bg-red-500" };
  if (status.degraded) return { label: "Needs attention", dot: "bg-orange-500" };
  return { label: "Running", dot: "bg-green-500" };
}

/** The helper daemon: whether it is installed and runs, and installing, reinstalling, and removing it. */
export function HelperSection() {
  const status = useStatus();
  const { service, pending, error, run } = useHelperService();
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const state = helperState(status.data, status.isError, service);
  const busy = pending !== undefined;
  return (
    <SettingsSection title="Helper Daemon">
      <div className="flex items-center justify-between">
        <div className="flex flex-col">
          <span className="text-sm font-medium">RouteWise Helper</span>
          {service ? (
            <span
              className={cn("text-xs", service.installed ? "text-green-600" : "text-muted-foreground")}
              data-testid="helper-installed">
              {service.installed ? "Installed" : "Not installed"}
            </span>
          ) : null}
        </div>
        <span className="flex items-center gap-1.5 text-xs" data-testid="helper-state">
          <span className={cn("size-2 rounded-full", state.dot)} aria-hidden />
          {state.label}
        </span>
      </div>
      {service ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" disabled={busy} onClick={() => run("install")}>
            {pending === "install" ? "Installing..." : service.installed ? "Reinstall Helper" : "Install Helper"}
          </Button>
          {service.installed ? (
            <Button variant="destructive" size="sm" disabled={busy} onClick={() => setConfirmUninstall(true)}>
              {pending === "uninstall" ? "Uninstalling..." : "Uninstall Helper"}
            </Button>
          ) : null}
        </div>
      ) : null}
      {status.data?.degraded && status.data.degradedReason ? (
        <Note tone="warning">{status.data.degradedReason}</Note>
      ) : null}
      {status.isError ? <Note tone="warning">{status.error.message}</Note> : null}
      {error ? <Outcome kind="error">{error}</Outcome> : null}
      <Note>The helper daemon runs in the background to manage VPN routes.</Note>

      <AlertDialog open={confirmUninstall} onOpenChange={setConfirmUninstall}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Uninstall the helper?</AlertDialogTitle>
            <AlertDialogDescription>
              RouteWise cannot route anything until the helper is installed again. You will be asked for an
              administrator password.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                setConfirmUninstall(false);
                run("uninstall");
              }}>
              Uninstall
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </SettingsSection>
  );
}
