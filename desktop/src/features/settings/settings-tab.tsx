"use client";

import { AppOptionsSection } from "./app-options-section";
import { ConfigurationSection } from "./configuration-section";
import { DnsSection } from "./dns-section";
import { ErrorReportingSection } from "./error-reporting-section";
import { HelperSection } from "./helper-section";
import { HistorySection } from "./history-section";
import { Ipv6Section } from "./ipv6-section";
import { LogsSection } from "./logs-section";
import { UpdatesSection } from "./updates-section";

/** Helper state, configuration, DNS, IPv6, history and logs, error reporting, the app's own options, and updates. */
export function SettingsTab({ onShowActivity }: { onShowActivity?: () => void }) {
  return (
    <div className="h-full overflow-auto" data-testid="settings-scroll">
      <div className="mx-auto flex max-w-2xl flex-col gap-3 p-4">
        <HelperSection />
        <ConfigurationSection />
        <DnsSection />
        <Ipv6Section />
        <HistorySection onShowActivity={onShowActivity} />
        <LogsSection />
        <ErrorReportingSection />
        <AppOptionsSection />
        <UpdatesSection />
      </div>
    </div>
  );
}
