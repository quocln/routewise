"use client";

import { Switch } from "@/components/ui/switch";
import { useSettings } from "@/lib/rpc/queries";
import { featureErrorMessage } from "@/features/activity/helper-feature-error";
import { Note, Outcome, SettingRow, SettingsSection } from "./settings-section";
import { useHelperAvailable } from "./use-helper-available";
import { useSettingsMutation } from "./use-settings-mutation";

/**
 * The "Allow IPv6" switch. RouteWise routes IPv4 only, so with IPv6 allowed a
 * listed name reached over IPv6 bypasses its VPN; off, the helper blocks those
 * addresses and apps fall back to IPv4.
 */
export function Ipv6Section() {
  const settings = useSettings();
  const available = useHelperAvailable();
  const save = useSettingsMutation();
  // The helper reports the setting only from the version that blocks IPv6.
  const supported = typeof settings.data?.allowIpv6 === "boolean";
  const allowed = save.isPending ? (save.variables.allowIpv6 ?? false) : (settings.data?.allowIpv6 ?? false);

  return (
    <SettingsSection title="IPv6">
      <SettingRow label="Allow IPv6 for listed domains">
        <Switch
          aria-label="Allow IPv6 for listed domains"
          checked={allowed}
          disabled={!available || !supported || save.isPending}
          onCheckedChange={(checked) => save.mutate({ allowIpv6: checked })}
        />
      </SettingRow>
      <Note>
        RouteWise sends only IPv4 through a VPN. While this is off, the IPv6 addresses of listed domains are blocked,
        so apps connect over IPv4 and go through the VPN. Turn it on only if a listed domain has no IPv4 address; on a
        network with IPv6 its traffic then goes direct.
      </Note>
      {settings.isSuccess && !supported ? <Note tone="warning">Needs a newer RouteWise helper.</Note> : null}
      {save.isError ? <Outcome kind="error">{`Could not change IPv6: ${featureErrorMessage(save.error)}`}</Outcome> : null}
    </SettingsSection>
  );
}
