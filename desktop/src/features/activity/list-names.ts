import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import type { ProfileInfo, Settings } from "@/lib/api/types.gen";
import { useSettings } from "@/lib/rpc/queries";
import { rpc } from "@/lib/rpc/rpc-client";

/** The client id of the shared "Any VPN" list. */
export const ANY_VPN_ID = "";

export type ListGroup = "any" | "builtIn" | "app";

export interface ListItem {
  id: string;
  group: ListGroup;
  title: string;
}

/** The profile id inside a built-in client id ("routewise-<kind>:<id>"), or undefined. */
export function profileIdOf(clientId: string): string | undefined {
  if (!clientId.startsWith("routewise-")) return undefined;
  const id = clientId.slice(clientId.indexOf(":") + 1);
  return clientId.includes(":") && id !== "" ? id : undefined;
}

/** Display names and kinds of the domain lists, by list id. A list that no longer exists keeps a readable name. */
export class ListNames {
  readonly items: ListItem[];
  private readonly byId: Map<string, ListItem>;

  constructor(items: ListItem[]) {
    this.items = items;
    this.byId = new Map();
    for (const item of items) if (!this.byId.has(item.id)) this.byId.set(item.id, item);
  }

  title(id: string): string {
    const item = this.byId.get(id);
    if (item) return item.title;
    if (id === ANY_VPN_ID) return "Any VPN";
    return profileIdOf(id) ?? id.split("/").filter(Boolean).pop() ?? id;
  }

  group(id: string): ListGroup {
    const item = this.byId.get(id);
    if (item) return item.group;
    return id === ANY_VPN_ID ? "any" : "builtIn";
  }
}

/** Builds the lists from the allowed clients and the built-in profiles. */
export function buildListNames(settings: Settings | undefined, profiles: ProfileInfo[] | undefined): ListNames {
  const items: ListItem[] = [{ id: ANY_VPN_ID, group: "any", title: "Any VPN" }];
  const clients = settings?.allowedVpnClients ?? [];
  for (const client of clients) {
    const display = client.name || client.id;
    if (profileIdOf(client.id) !== undefined) {
      const profile = profiles?.find((p) => p.id === profileIdOf(client.id));
      items.push({ id: client.id, group: "builtIn", title: profile?.name || display });
    } else {
      items.push({ id: client.id, group: "app", title: display });
    }
  }
  return new ListNames(items);
}

/** The domain lists with their names, for rows and the List filter. */
export function useListNames(): ListNames {
  const settings = useSettings();
  const profiles = useQuery({ queryKey: ["profiles.list"], queryFn: () => rpc("profiles.list") });
  return useMemo(() => buildListNames(settings.data, profiles.data), [settings.data, profiles.data]);
}
