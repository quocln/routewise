"use client";

import { MainBanners } from "@/components/main-banners";
import { ActivityTab } from "@/features/activity/activity-tab";
import { DashboardTab } from "@/features/dashboard/dashboard-tab";
import { DomainsTab } from "@/features/domains/domains-tab";
import { RoutesTab } from "@/features/routes/routes-tab";
import { SettingsTab } from "@/features/settings/settings-tab";
import { useUpdateAvailableListener } from "@/features/settings/use-update-info";
import { StatusHeader } from "@/features/status/status-header";
import { VpnTab } from "@/features/vpn/vpn-tab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useShellNavigation } from "@/lib/native/use-shell-navigation";
import { useStatusFeed } from "@/lib/rpc/use-status-feed";
import { usePersistedState, writeStored } from "@/lib/use-persisted-state";

const TABS = [
  { value: "dashboard", label: "Dashboard" },
  { value: "domains", label: "Domains" },
  { value: "vpn", label: "VPN" },
  { value: "routes", label: "Routes" },
  { value: "activity", label: "Activity" },
  { value: "settings", label: "Settings" },
] as const;

type TabValue = (typeof TABS)[number]["value"];

function isTabValue(value: unknown): value is TabValue {
  return TABS.some((tab) => tab.value === value);
}

/** The window: status header above the tabs. */
export function AppShell() {
  const [tab, setTab] = usePersistedState<TabValue>("tab", "domains", isTabValue);
  // A release the shell finds in the background shows in Settings whenever it is opened.
  useUpdateAvailableListener();
  useStatusFeed();
  // The tray's Manage/View/Settings items choose the tab; unknown names are
  // ignored. View Activity shows connections.
  useShellNavigation((requested) => {
    if (!isTabValue(requested)) return;
    if (requested === "activity") writeStored("activity.segment", "connections");
    setTab(requested);
  });
  // The Domains tab follows its stored selection, so choosing a list for it is
  // a write to that key; client ids are the list ids.
  const editDomains = (clientId: string) => {
    writeStored("domains.selectedList", clientId);
    setTab("domains");
  };
  return (
    <div className="flex h-full flex-col">
      <StatusHeader />
      <MainBanners />
      <Tabs
        value={tab}
        onValueChange={(value) => isTabValue(value) && setTab(value)}
        className="min-h-0 flex-1 gap-0">
        <TabsList variant="line" className="px-3 pt-2">
          {TABS.map((tab) => (
            <TabsTrigger key={tab.value} value={tab.value}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="dashboard" className="min-h-0 flex-1">
          <DashboardTab />
        </TabsContent>
        <TabsContent value="domains" className="min-h-0 flex-1">
          <DomainsTab onOpenVpnTab={() => setTab("vpn")} />
        </TabsContent>
        <TabsContent value="vpn" className="min-h-0 flex-1">
          <VpnTab onEditDomains={editDomains} />
        </TabsContent>
        <TabsContent value="routes" className="min-h-0 flex-1">
          <RoutesTab />
        </TabsContent>
        <TabsContent value="activity" className="min-h-0 flex-1">
          <ActivityTab />
        </TabsContent>
        <TabsContent value="settings" className="min-h-0 flex-1">
          <SettingsTab onShowActivity={() => setTab("activity")} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
