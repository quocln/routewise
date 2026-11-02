"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
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
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import type { Export as ConfigExport } from "@/lib/api/config.gen";
import { openTextFile, saveTextFile } from "@/lib/native/native-commands";
import { NativeError } from "@/lib/native/native-error";
import { rpc } from "@/lib/rpc/rpc-client";
import {
  CONFIG_FILE_FILTER,
  TransferError,
  defaultFileName,
  parseConfigDocument,
  prettyPrint,
} from "./config-transfer";
import { Note, Outcome, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";

/** The text to show for a failed step: the shell's own words, or the helper's. */
function errorText(error: unknown): string {
  return error instanceof NativeError ? error.message : featureErrorMessage(error);
}

interface PendingImport {
  name: string;
  document: ConfigExport;
}

/** Export and import of the helper's configuration. */
export function ConfigurationSection() {
  const available = useHelperAvailable();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [restartRequired, setRestartRequired] = useState(false);
  const [pending, setPending] = useState<PendingImport | null>(null);

  const reset = () => {
    setMessage(null);
    setError(null);
    setRestartRequired(false);
  };

  // A save the user cancelled resolves to null and says nothing.
  const exportConfig = useMutation({
    mutationFn: async () => {
      const text = prettyPrint(await rpc("config.export"));
      const saved = await saveTextFile(defaultFileName(), text, CONFIG_FILE_FILTER);
      return saved === null ? null : `Exported to ${saved}.`;
    },
    onMutate: reset,
    onSuccess: setMessage,
    onError: (e) => setError(`Could not export: ${errorText(e)}`),
  });

  const importConfig = useMutation({
    mutationFn: (item: PendingImport) => rpc("config.import", { config: item.document }),
    onMutate: reset,
    onSuccess: (result, item) => {
      setMessage(`Imported ${item.name}.`);
      setRestartRequired(result.restartRequired);
      // The import replaced lists, clients and settings, so everything shown may have changed.
      void queryClient.invalidateQueries();
    },
    onError: (e) => setError(`Could not import: ${errorText(e)}`),
  });

  const chooseFile = useMutation({
    mutationFn: openTextFile,
    onMutate: reset,
    onSuccess: (file) => {
      if (file === null) return;
      try {
        setPending({ name: file.name, document: parseConfigDocument(file.contents) });
      } catch (e) {
        setError(`Could not read ${file.name}: ${e instanceof TransferError ? e.message : String(e)}`);
      }
    },
    onError: (e) => setError(`Could not open the file: ${errorText(e)}`),
  });

  const busy = exportConfig.isPending || importConfig.isPending || chooseFile.isPending;
  return (
    <SettingsSection title="Configuration">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" disabled={!available || busy} onClick={() => exportConfig.mutate()}>
          Export…
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!available || busy}
          onClick={() => chooseFile.mutate(CONFIG_FILE_FILTER)}>
          Import…
        </Button>
      </div>
      <Note>
        Export saves domain lists, allowed VPN clients and DNS settings to a file. Import replaces them with a
        file&apos;s.
      </Note>
      {message ? <Outcome kind="ok">{message}</Outcome> : null}
      {restartRequired ? (
        <p className="text-xs text-orange-500 select-text">
          Restart the helper to apply the imported settings: run <code>sudo routewise restart</code> in Terminal.
        </p>
      ) : null}
      {error ? <Outcome kind="error">{error}</Outcome> : null}

      <AlertDialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{`Import ${pending?.name ?? ""}?`}</AlertDialogTitle>
            <AlertDialogDescription>
              Replace domain lists, allowed VPN clients, and DNS settings with the file&apos;s?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pending) importConfig.mutate(pending);
                setPending(null);
              }}>
              Replace
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </SettingsSection>
  );
}
