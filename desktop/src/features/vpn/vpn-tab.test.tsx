import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// What the helper answers, by method; a function may throw an RPC error payload.
type Handler = (params: unknown) => unknown;
let helper: Record<string, Handler> = {};
const calls: { method: string; params: unknown }[] = [];

// A plain function, not vi.fn(): the test runner reports a rejection returned
// by a spy as unhandled, while the real `invoke` is awaited by the client.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (_command: string, args: { method: string; params: unknown }) => {
    calls.push({ method: args.method, params: args.params });
    const handler = helper[args.method];
    if (!handler) return Promise.reject({ kind: "remote", code: -32601, message: "method not found" });
    try {
      return Promise.resolve(handler(args.params));
    } catch (error) {
      return Promise.reject(error);
    }
  },
  isTauri: () => true,
}));

const { VpnTab } = await import("./vpn-tab");

// Obviously fake: nothing here is, or looks like, a real key.
const FAKE_CONFIG = "[Interface]\nPrivateKey = FAKE-NOT-A-REAL-KEY\n";
const FAKE_OUTLINE_KEY = "ss://FAKE-NOT-A-REAL-KEY@example.invalid:1";

const profile = (over: Record<string, unknown> = {}) => ({
  id: "p1",
  kind: "wireguard",
  name: "Work",
  autoConnect: false,
  dns: [],
  state: "disconnected",
  ...over,
});

const settings = (over: Record<string, unknown> = {}) => ({
  useVpnDns: false,
  allowIpv6: false,
  defaultVpn: "",
  defaultVpnFallback: "",
  allowedVpnClients: [],
  historyEnabled: true,
  historyRetentionDays: 30,
  ...over,
});

const upStatus = (over: Record<string, unknown> = {}) => ({ running: true, vpnConnected: false, routeCount: 0, ...over });

function serve(over: Record<string, Handler> = {}) {
  helper = {
    "status.get": () => upStatus(),
    "settings.get": () => settings(),
    "profiles.list": () => [],
    "domains.list": () => [],
    ...over,
  };
}

function renderTab(props: { onEditDomains?: (id: string) => void } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VpnTab {...props} />
    </QueryClientProvider>,
  );
}

function callsTo(method: string) {
  return calls.filter((c) => c.method === method);
}

describe("VpnTab", () => {
  beforeEach(() => {
    calls.length = 0;
    serve();
  });

  describe("built-in profiles", () => {
    it("explains an empty list once the helper has answered", async () => {
      renderTab();
      expect(await screen.findByText(/No built-in VPNs yet/)).toBeInTheDocument();
    });

    it("shows a connected profile with its server, traffic, routes and domain count", async () => {
      serve({
        "status.get": () =>
          upStatus({
            vpnConnected: true,
            tunnels: [{ interface: "utun7", client: { id: "routewise-wireguard:p1", name: "Work" }, routeCount: 4, profileId: "p1" }],
          }),
        "profiles.list": () => [
          profile({ state: "connected", interface: "utun7", server: "vpn.example.invalid:51820", stats: { rxBytes: 1536, txBytes: 200 } }),
        ],
        "domains.list": () => [{ pattern: "a.example.invalid" }, { pattern: "b.example.invalid" }],
      });
      renderTab();
      const card = await screen.findByTestId("profile-p1");
      await waitFor(() => expect(within(card).getByTestId("profile-state")).toHaveTextContent("Connected via utun7 · 4 routes"));
      expect(within(card).getByText("vpn.example.invalid:51820")).toBeInTheDocument();
      expect(within(card).getByText(/1\.5 KB/)).toBeInTheDocument();
      expect(await within(card).findByText("2 entries go through this VPN")).toBeInTheDocument();
      expect(within(card).getByRole("button", { name: "Disconnect" })).toBeEnabled();
      expect(callsTo("domains.list").map((c) => c.params)).toContainEqual({ vpn: "routewise-wireguard:p1" });
    });

    it("connects a profile and shows it switching until the list confirms", async () => {
      let state = "disconnected";
      let finish: () => void = () => {};
      serve({
        "profiles.list": () => [profile({ state })],
        "profiles.connect": () =>
          new Promise((resolve) => {
            finish = () => {
              state = "connected";
              resolve({ success: true });
            };
          }),
      });
      renderTab();
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "Connect" }));

      expect(await screen.findByText("Connecting…")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
      expect(callsTo("profiles.connect")[0].params).toEqual({ id: "p1" });

      finish();
      expect(await screen.findByRole("button", { name: "Disconnect" })).toBeInTheDocument();
      await waitFor(() => expect(screen.queryByText("Connecting…")).not.toBeInTheDocument());
    });

    it("reports a failed connect and keeps the profile off", async () => {
      serve({
        "profiles.list": () => [profile()],
        "profiles.connect": () => {
          throw { kind: "remote", code: -32000, message: "tunnel refused" };
        },
      });
      renderTab();
      await userEvent.setup().click(await screen.findByRole("button", { name: "Connect" }));
      expect(await screen.findByText("Could not connect Work: tunnel refused")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Connect" })).toBeEnabled();
    });

    it("offers Disconnect for a profile that is failing and retrying, with its error", async () => {
      serve({ "profiles.list": () => [profile({ state: "error", error: "handshake timed out" })] });
      renderTab();
      const card = await screen.findByTestId("profile-p1");
      expect(within(card).getByRole("button", { name: "Disconnect" })).toBeInTheDocument();
      expect(within(card).getByTestId("profile-state")).toHaveTextContent("Not working — retrying");
      expect(within(card).getByRole("alert")).toHaveTextContent("handshake timed out");
    });

    it("asks for a key when a profile has none and hides the startup option", async () => {
      serve({ "profiles.list": () => [profile({ state: "needsCredentials" })] });
      renderTab();
      const card = await screen.findByTestId("profile-p1");
      expect(within(card).getByRole("button", { name: "Add Key/Config…" })).toBeInTheDocument();
      expect(within(card).getByText(/No key or config yet/)).toBeInTheDocument();
      expect(within(card).queryByRole("checkbox")).not.toBeInTheDocument();
    });

    it("turns auto-connect on through profiles.update", async () => {
      serve({ "profiles.list": () => [profile()], "profiles.update": () => ({ success: true }) });
      renderTab();
      const user = userEvent.setup();
      await user.click(await screen.findByRole("checkbox", { name: /Connect automatically/ }));
      await waitFor(() => expect(callsTo("profiles.update")).toHaveLength(1));
      expect(callsTo("profiles.update")[0].params).toEqual({ id: "p1", autoConnect: true });
    });

    it("removes a profile only after confirmation", async () => {
      serve({ "profiles.list": () => [profile()], "profiles.remove": () => ({ success: true }) });
      renderTab();
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "More actions for Work" }));
      await user.click(await screen.findByRole("menuitem", { name: "Remove…" }));
      const dialog = await screen.findByRole("alertdialog");
      expect(dialog).toHaveTextContent("Remove Work?");
      expect(callsTo("profiles.remove")).toHaveLength(0);

      await user.click(within(dialog).getByRole("button", { name: "Remove" }));
      await waitFor(() => expect(callsTo("profiles.remove")).toHaveLength(1));
      expect(callsTo("profiles.remove")[0].params).toEqual({ id: "p1" });
    });

    it("renames a profile", async () => {
      serve({ "profiles.list": () => [profile()], "profiles.update": () => ({ success: true }) });
      renderTab();
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "More actions for Work" }));
      await user.click(await screen.findByRole("menuitem", { name: "Rename…" }));
      const name = await screen.findByLabelText("Name");
      await user.clear(name);
      await user.type(name, "  Office  ");
      await user.click(screen.getByRole("button", { name: "Rename" }));
      await waitFor(() => expect(callsTo("profiles.update")).toHaveLength(1));
      expect(callsTo("profiles.update")[0].params).toEqual({ id: "p1", name: "Office" });
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    });

    it("jumps to a profile's domains when the window can", async () => {
      serve({ "profiles.list": () => [profile()] });
      const onEditDomains = vi.fn();
      renderTab({ onEditDomains });
      const card = await screen.findByTestId("profile-p1");
      await userEvent.setup().click(within(card).getByRole("button", { name: "Edit Domains…" }));
      expect(onEditDomains).toHaveBeenCalledWith("routewise-wireguard:p1");
    });

    it("hides the domain shortcuts when the window cannot jump", async () => {
      serve({ "profiles.list": () => [profile()] });
      renderTab();
      const card = await screen.findByTestId("profile-p1");
      expect(within(card).queryByRole("button", { name: "Edit Domains…" })).not.toBeInTheDocument();
    });
  });

  describe("importing", () => {
    it("imports a WireGuard config file, sending its text only in the request", async () => {
      serve({ "profiles.import": () => ({ id: "new" }) });
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Import WireGuard/ }));
      await user.upload(screen.getByTestId("wireguard-file-input"), new File([FAKE_CONFIG], "office.conf"));

      const name = await screen.findByLabelText("Name");
      expect(name).toHaveValue("office");
      await user.click(screen.getByRole("button", { name: "Import" }));

      await waitFor(() => expect(callsTo("profiles.import")).toHaveLength(1));
      expect(callsTo("profiles.import")[0].params).toEqual({ kind: "wireguard", name: "office", wireguardConfig: FAKE_CONFIG });
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      // The text is not shown anywhere in the page.
      expect(document.body).not.toHaveTextContent("FAKE-NOT-A-REAL-KEY");
    });

    it("says which file could not be used without showing its content", async () => {
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Import WireGuard/ }));
      await user.upload(screen.getByTestId("wireguard-file-input"), new File([new Uint8Array([0xff, 0xfe])], "bad.conf"));
      await user.click(await screen.findByRole("button", { name: "Import" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("bad.conf is not a text file.");
      expect(callsTo("profiles.import")).toHaveLength(0);
    });

    it("adds an Outline key and clears the field", async () => {
      serve({ "profiles.import": () => ({ id: "new" }) });
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Add Outline Key/ }));
      const submit = await screen.findByRole("button", { name: "Add" });
      expect(submit).toBeDisabled();
      const key = screen.getByLabelText("Access key");
      expect(key).toHaveAttribute("type", "password");
      await user.type(screen.getByLabelText("Name"), "Travel");
      await user.type(key, `  ${FAKE_OUTLINE_KEY}  `);
      await user.click(submit);

      await waitFor(() => expect(callsTo("profiles.import")).toHaveLength(1));
      expect(callsTo("profiles.import")[0].params).toEqual({ kind: "outline", name: "Travel", accessKey: FAKE_OUTLINE_KEY });
    });

    it("rejects a malformed key before sending anything", async () => {
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Add Outline Key/ }));
      await user.type(await screen.findByLabelText("Name"), "Travel");
      await user.type(screen.getByLabelText("Access key"), "https://example.invalid/not-a-key");
      await user.click(screen.getByRole("button", { name: "Add" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("The key must start with ss:// or ssconf://.");
      expect(callsTo("profiles.import")).toHaveLength(0);
    });

    it("shows the helper's refusal, keeps the dialog open and empties the key field", async () => {
      serve({
        "profiles.import": () => {
          throw { kind: "remote", code: -32602, message: "invalid access key" };
        },
      });
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Add Outline Key/ }));
      await user.type(await screen.findByLabelText("Name"), "Travel");
      await user.type(screen.getByLabelText("Access key"), FAKE_OUTLINE_KEY);
      await user.click(screen.getByRole("button", { name: "Add" }));
      expect(await screen.findByText("invalid access key")).toBeInTheDocument();
      expect(screen.getByLabelText("Access key")).toHaveValue("");
      expect(document.body).not.toHaveTextContent("FAKE-NOT-A-REAL-KEY");
    });

    it("tells the user to reinstall an older helper that lacks profiles.import", async () => {
      renderTab();
      const user = userEvent.setup();
      await screen.findByText(/No built-in VPNs yet/);
      await user.click(screen.getByRole("button", { name: /Add Outline Key/ }));
      await user.type(await screen.findByLabelText("Name"), "Travel");
      await user.type(screen.getByLabelText("Access key"), FAKE_OUTLINE_KEY);
      await user.click(screen.getByRole("button", { name: "Add" }));
      expect(await screen.findByText("Reinstall the helper to use this feature.")).toBeInTheDocument();
    });

    it("replaces the key of an Outline profile through profiles.update", async () => {
      serve({ "profiles.list": () => [profile({ kind: "outline" })], "profiles.update": () => ({ success: true }) });
      renderTab();
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "More actions for Work" }));
      await user.click(await screen.findByRole("menuitem", { name: "Replace Key/Config…" }));
      await user.type(await screen.findByLabelText("Access key"), FAKE_OUTLINE_KEY);
      await user.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(callsTo("profiles.update")).toHaveLength(1));
      expect(callsTo("profiles.update")[0].params).toEqual({ id: "p1", accessKey: FAKE_OUTLINE_KEY });
    });
  });

  describe("VPN apps", () => {
    const aws = { id: "/Applications/AWS VPN Client.app", name: "AWS VPN Client" };
    const wireguardApp = { id: "/Applications/WireGuard.app", name: "WireGuard" };

    it("lists managed apps in priority order, leaving built-in profiles to their own section", async () => {
      serve({
        "settings.get": () => settings({ allowedVpnClients: [aws, { id: "routewise-wireguard:p1", name: "Work" }, wireguardApp] }),
        "domains.list": () => [{ pattern: "x.example.invalid" }],
        "status.get": () =>
          upStatus({ vpnConnected: true, tunnels: [{ interface: "utun4", client: aws, routeCount: 1 }] }),
      });
      renderTab();
      const items = await screen.findAllByRole("listitem");
      expect(items).toHaveLength(2);
      expect(items[0]).toHaveTextContent("1AWS VPN ClientConnected");
      expect(items[1]).toHaveTextContent("2WireGuardNot connected");
      expect(await within(items[0]).findByText("1 entry")).toBeInTheDocument();
    });

    describe("default VPN", () => {
      const builtIn = { id: "routewise-wireguard:p1", name: "Work" };

      async function pick(user: ReturnType<typeof userEvent.setup>, control: string, option: string) {
        await waitFor(() => expect(screen.getByRole("combobox", { name: control })).toBeEnabled());
        await user.click(screen.getByRole("combobox", { name: control }));
        await user.click(await screen.findByRole("option", { name: option }));
      }

      it("offers VPN apps and built-in VPNs alike, and saves the choice", async () => {
        const user = userEvent.setup();
        serve({
          "settings.get": () => settings({ allowedVpnClients: [aws, builtIn] }),
          "settings.set": () => settings({ allowedVpnClients: [aws, builtIn], defaultVpn: aws.id }),
        });
        renderTab();
        await pick(user, "Default VPN", "AWS VPN Client");
        await waitFor(() => expect(callsTo("settings.set")).toHaveLength(1));
        expect(callsTo("settings.set")[0].params).toEqual({ defaultVpn: aws.id });
      });

      it("keeps the fallback choice off until a default VPN is chosen", async () => {
        serve({ "settings.get": () => settings({ allowedVpnClients: [aws, builtIn] }) });
        renderTab();
        await waitFor(() => expect(screen.getByRole("combobox", { name: "Default VPN" })).toBeEnabled());
        expect(screen.getByRole("combobox", { name: "If the default VPN goes down" })).toBeDisabled();
      });

      it("never offers the default VPN as its own fallback", async () => {
        const user = userEvent.setup();
        serve({
          "settings.get": () => settings({ allowedVpnClients: [aws, builtIn], defaultVpn: aws.id }),
          "settings.set": () => settings({ allowedVpnClients: [aws, builtIn], defaultVpn: aws.id, defaultVpnFallback: builtIn.id }),
        });
        renderTab();
        await waitFor(() => expect(screen.getByRole("combobox", { name: "If the default VPN goes down" })).toBeEnabled());
        await user.click(screen.getByRole("combobox", { name: "If the default VPN goes down" }));
        expect(await screen.findByRole("option", { name: "Switch to Work" })).toBeInTheDocument();
        expect(screen.queryByRole("option", { name: "Switch to AWS VPN Client" })).toBeNull();
        await user.click(screen.getByRole("option", { name: "Switch to Work" }));
        await waitFor(() => expect(callsTo("settings.set")).toHaveLength(1));
        expect(callsTo("settings.set")[0].params).toEqual({ defaultVpnFallback: builtIn.id });
      });

      it("clears the fallback together with the default VPN", async () => {
        const user = userEvent.setup();
        serve({
          "settings.get": () => settings({ allowedVpnClients: [aws, builtIn], defaultVpn: aws.id, defaultVpnFallback: builtIn.id }),
          "settings.set": () => settings({ allowedVpnClients: [aws, builtIn] }),
        });
        renderTab();
        await pick(user, "Default VPN", "No VPN (direct)");
        await waitFor(() => expect(callsTo("settings.set")).toHaveLength(1));
        expect(callsTo("settings.set")[0].params).toEqual({ defaultVpn: "", defaultVpnFallback: "" });
      });

      it.each([
        [{ state: "primary", activeClient: "SG", activeInterface: "utun7" }, "Other traffic goes through SG (utun7)."],
        [
          { state: "fallback", activeClient: "Work", activeInterface: "utun6" },
          "The default VPN is unavailable. Other traffic goes through Work (utun6).",
        ],
        [{ state: "direct" }, "The default VPN is not connected. Other traffic goes direct."],
      ])("says who carries the traffic now: %o", async (defaultVpn, text) => {
        serve({
          "settings.get": () => settings({ allowedVpnClients: [aws], defaultVpn: aws.id }),
          "status.get": () => upStatus({ defaultVpn: { client: aws.id, ...defaultVpn } }),
        });
        renderTab();
        expect(await screen.findByText(text)).toBeInTheDocument();
      });

      it("shows why a connected VPN was passed over", async () => {
        const problem = "Work cannot be the default VPN: all traffic is outside the peer's AllowedIPs";
        serve({
          "settings.get": () => settings({ allowedVpnClients: [builtIn], defaultVpn: builtIn.id }),
          "status.get": () => upStatus({ defaultVpn: { client: builtIn.id, state: "direct", problem } }),
        });
        renderTab();
        expect(await screen.findByText(problem)).toBeInTheDocument();
      });

      it("says so when the helper is too old for the setting", async () => {
        serve({ "settings.get": () => ({ useVpnDns: false, allowIpv6: false, allowedVpnClients: [aws] }) });
        renderTab();
        expect(await screen.findByText("Needs a newer RouteWise helper.")).toBeInTheDocument();
        expect(screen.getByRole("combobox", { name: "Default VPN" })).toBeDisabled();
      });
    });

    it("explains how apps get managed when there are none", async () => {
      renderTab();
      expect(await screen.findByText(/RouteWise asks before managing a VPN app/)).toBeInTheDocument();
    });

    it("stops managing an app through vpn.setAllowed", async () => {
      serve({
        "settings.get": () => settings({ allowedVpnClients: [aws] }),
        "vpn.setAllowed": () => settings({ allowedVpnClients: [] }),
      });
      renderTab();
      await userEvent.setup().click(await screen.findByRole("button", { name: "Remove" }));
      expect(callsTo("vpn.setAllowed")[0].params).toEqual({ clientId: aws.id, allowed: false });
      expect(await screen.findByText(/RouteWise asks before managing a VPN app/)).toBeInTheDocument();
    });

    it("shows why removing an app failed", async () => {
      serve({
        "settings.get": () => settings({ allowedVpnClients: [aws] }),
        "vpn.setAllowed": () => {
          throw { kind: "remote", code: -32001, message: "not authorized" };
        },
      });
      renderTab();
      await userEvent.setup().click(await screen.findByRole("button", { name: "Remove" }));
      expect(await screen.findByText("Could not remove AWS VPN Client: not authorized")).toBeInTheDocument();
    });
  });

  describe("VPN DNS", () => {
    it("turns the switch on through settings.set and then shows the helper's value", async () => {
      let useVpnDns = false;
      serve({
        "status.get": () => upStatus({ useVpnDns, vpnDnsServers: ["10.0.0.2"] }),
        "settings.set": (params) => {
          useVpnDns = (params as { useVpnDns: boolean }).useVpnDns;
          return settings({ useVpnDns });
        },
      });
      renderTab();
      const user = userEvent.setup();
      const toggle = await screen.findByRole("switch", { name: "Use the VPN's DNS servers" });
      expect(await screen.findByText("VPN DNS: 10.0.0.2")).toBeInTheDocument();
      expect(toggle).not.toBeChecked();
      await user.click(toggle);
      expect(callsTo("settings.set")[0].params).toEqual({ useVpnDns: true });
      await waitFor(() => expect(toggle).toBeChecked());
    });

    it("falls back to the helper's value when the change fails", async () => {
      serve({
        "settings.set": () => {
          throw { kind: "remote", code: -32000, message: "could not save" };
        },
      });
      renderTab();
      const toggle = await screen.findByRole("switch");
      await userEvent.setup().click(toggle);
      expect(await screen.findByText("Could not change VPN DNS: could not save")).toBeInTheDocument();
      expect(toggle).not.toBeChecked();
    });
  });

  describe("helper unavailable", () => {
    beforeEach(() => {
      const gone = () => {
        throw { kind: "unavailable", message: "No such file or directory" };
      };
      serve({ "status.get": gone, "settings.get": gone, "profiles.list": gone, "domains.list": gone });
    });

    it("disables every control and says why", async () => {
      renderTab();
      expect((await screen.findAllByText(/Unavailable until the app reconnects/)).length).toBeGreaterThan(0);
      expect(screen.getByText("Built-in VPNs appear here once the helper answers.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Import WireGuard/ })).toBeDisabled();
      expect(screen.getByRole("button", { name: /Add Outline Key/ })).toBeDisabled();
      expect(screen.getByRole("switch")).toHaveAttribute("aria-disabled", "true");
    });
  });
});
