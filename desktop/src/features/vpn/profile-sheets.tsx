"use client";

import type { ProfileInfo } from "@/lib/api/types.gen";
import { ProfileEntryDialog } from "./profile-entry-dialog";
import { ProxyEntryDialog } from "./proxy-entry-dialog";
import type { ProfileActions } from "./use-profile-actions";
import { displayName, kindTitle, type ProxyKind } from "./vpn-format";
import { nameFromFile, readWireGuardConfig } from "./wireguard-config-file";

/**
 * What the open dialog is for. A WireGuard file is held as the picked `File`,
 * never as text: it is read at the moment it is sent.
 */
export type ProfileSheet =
  | { kind: "importWireGuard"; file: File }
  | { kind: "addOutline" }
  | { kind: "addProxy"; proxy: ProxyKind }
  | { kind: "replaceProxy"; proxy: ProxyKind; profile: ProfileInfo }
  | { kind: "rename"; profile: ProfileInfo }
  | { kind: "replaceOutlineKey"; profile: ProfileInfo }
  | { kind: "replaceWireGuardConfig"; profile: ProfileInfo; file: File };

interface Props {
  sheet: ProfileSheet | null;
  onClose: () => void;
  actions: Pick<ProfileActions, "importProfile" | "setSecret" | "rename">;
}

/** The dialog for the open sheet, or a closed one. */
export function ProfileSheetHost({ sheet, onClose, actions }: Props) {
  const common = { open: sheet !== null, onClose };
  switch (sheet?.kind) {
    case "importWireGuard": {
      const { file } = sheet;
      return (
        <ProfileEntryDialog
          {...common}
          title="Import WireGuard config"
          confirmLabel="Import"
          initialName={nameFromFile(file)}
          askKey={false}
          submit={async (name) => {
            const wireguardConfig = await readWireGuardConfig(file);
            await actions.importProfile({ kind: "wireguard", name, wireguardConfig });
          }}
        />
      );
    }
    case "addOutline":
      return (
        <ProfileEntryDialog
          {...common}
          title="Add Outline key"
          confirmLabel="Add"
          explanation="Paste the ss:// key or ssconf:// URL from your Outline server admin."
          initialName=""
          askKey
          submit={async (name, accessKey) => {
            await actions.importProfile({ kind: "outline", name, accessKey });
          }}
        />
      );
    case "addProxy": {
      const { proxy } = sheet;
      return (
        <ProxyEntryDialog
          {...common}
          proxy={proxy}
          title={proxy === "http" ? "Add HTTP proxy" : "Add SOCKS5 proxy"}
          confirmLabel="Add"
          askName
          submit={async (name, accessKey) => {
            await actions.importProfile({ kind: proxy, name, accessKey });
          }}
        />
      );
    }
    case "replaceProxy": {
      const { profile, proxy } = sheet;
      return (
        <ProxyEntryDialog
          {...common}
          proxy={proxy}
          title={`${kindTitle(proxy)} for ${displayName(profile.name, profile.id)}`}
          confirmLabel="Save"
          askName={false}
          submit={(_, address) => actions.setSecret(profile, address)}
        />
      );
    }
    case "rename": {
      const { profile } = sheet;
      return (
        <ProfileEntryDialog
          {...common}
          title={`Rename ${profile.name}`}
          confirmLabel="Rename"
          initialName={profile.name}
          askKey={false}
          submit={(name) => actions.rename(profile, name)}
        />
      );
    }
    case "replaceOutlineKey": {
      const { profile } = sheet;
      return (
        <ProfileEntryDialog
          {...common}
          title={`Outline key for ${displayName(profile.name, profile.id)}`}
          confirmLabel="Save"
          explanation="The new key replaces the stored one."
          initialName={null}
          askKey
          submit={(_, key) => actions.setSecret(profile, key)}
        />
      );
    }
    case "replaceWireGuardConfig": {
      const { profile, file } = sheet;
      return (
        <ProfileEntryDialog
          {...common}
          title={`Replace config for ${displayName(profile.name, profile.id)}`}
          confirmLabel="Replace"
          explanation={`Use ${file.name} as the new config?`}
          initialName={null}
          askKey={false}
          submit={async () => actions.setSecret(profile, await readWireGuardConfig(file))}
        />
      );
    }
    default:
      return null;
  }
}
