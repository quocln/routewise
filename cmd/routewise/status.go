package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/daemon"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon and VPN status",
	Long: `Display the current status of the VPN routing daemon.

Shows:
- Daemon running state and PID
- VPN connection status and interface, as reported by the helper
- Wildcard routing and VPN DNS state
- Number of configured domains
- Active route count

Examples:
  routewise status`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	pid, running := daemon.CheckPIDFile(cfg.Daemon.PidFile)
	if running {
		fmt.Printf("Daemon:  running (pid %d)\n", pid)
	} else {
		fmt.Println("Daemon:  stopped")
	}

	// The helper is the only component that knows which tunnel RouteWise is
	// actually managing. Guessing from the presence of a utun device would report
	// an unrelated tunnel as a managed VPN connection.
	ctx := commandContext(cmd)
	var status api.StatusResult
	if running, err := callHelper(ctx, "status.get", nil, &status); running {
		if err != nil {
			return fmt.Errorf("query helper status: %w", err)
		}
		printHelperStatus(status)
	} else {
		fmt.Println("VPN:     unknown (start the helper to see live status)")
	}

	configPath := getConfigPath()
	if dbPath := configdb.PathFor(configPath); fileExists(dbPath) {
		configPath = dbPath
	}
	fmt.Printf("Config:  %s\n", configPath)

	// Ask the helper rather than counting the file we just loaded: the config is
	// readable only by root, so an unprivileged caller would otherwise fall back
	// to the empty defaults and report zero domains while routing is active.
	patterns, err := configuredDomains(ctx)
	if err != nil {
		fmt.Println("Domains: unknown (config not readable and helper not reachable)")
		return nil
	}

	// The patterns above are the Any VPN list only; the helper counts every list.
	// A helper too old to report the count leaves it at zero.
	fmt.Printf("Domains: %d patterns configured\n", max(len(patterns), status.DomainCount))
	if verbose && len(patterns) > 0 {
		fmt.Println("\nAny VPN domains:")
		for _, p := range patterns {
			fmt.Printf("  - %s\n", p)
		}
	}

	return nil
}

// printHelperStatus renders live helper state.
// printDefaultVPN says where traffic no list claims goes. It prints nothing while
// no default VPN is set.
func printDefaultVPN(d *api.DefaultVPNStatus) {
	if d == nil {
		return
	}
	switch d.State {
	case api.DefaultVPNPrimary:
		fmt.Printf("Default: other traffic goes through %s (%s)\n", d.ActiveClient, d.ActiveInterface)
	case api.DefaultVPNFallback:
		fmt.Printf("Default: default VPN unavailable, other traffic goes through fallback %s (%s)\n", d.ActiveClient, d.ActiveInterface)
	default:
		fmt.Println("Default: other traffic goes direct")
	}
	if d.Problem != "" {
		fmt.Printf("Default: %s\n", d.Problem)
	}
}

func printHelperStatus(status api.StatusResult) {
	if status.Degraded {
		fmt.Printf("State:   degraded: %s\n", status.DegradedReason)
	}

	switch {
	case status.VPNConnected && status.VPNInterface != "" && status.VPNClient != nil:
		fmt.Printf("VPN:     connected (%s, %s)\n", status.VPNInterface, status.VPNClient.Name)
	case status.VPNConnected && status.VPNInterface != "":
		fmt.Printf("VPN:     connected (%s)\n", status.VPNInterface)
	case status.VPNConnected:
		fmt.Println("VPN:     connected")
	case status.PendingVPN != nil:
		for _, p := range pendingVPNs(status) {
			fmt.Printf("VPN:     %s on %s detected, not managed: allow its client in the RouteWise app\n",
				p.Client.Name, p.Interface)
		}
	default:
		fmt.Println("VPN:     disconnected")
	}
	// With several tunnels the line above names only the highest-priority one.
	if len(status.Tunnels) > 1 {
		for i, t := range status.Tunnels {
			name := t.Client.Name
			if name == "" {
				name = "unidentified client"
			}
			fmt.Printf("Tunnel:  %d. %s (%s), %d routes\n", i+1, t.Interface, name, t.RouteCount)
		}
	}
	fmt.Printf("Routes:  %d managed by RouteWise\n", status.RouteCount)
	printDefaultVPN(status.DefaultVPN)

	switch {
	case len(status.VPNDNSServers) > 0 && status.UseVPNDNS:
		fmt.Printf("DNS:     resolving through VPN DNS %s\n", strings.Join(status.VPNDNSServers, ", "))
	case len(status.VPNDNSServers) > 0:
		fmt.Printf("DNS:     VPN DNS %s routed through the tunnel (dns.use_vpn_dns off)\n", strings.Join(status.VPNDNSServers, ", "))
	case status.UseVPNDNS && status.VPNConnected:
		fmt.Println("DNS:     waiting for the VPN to publish its DNS servers")
	}
	if len(status.WildcardDomains) > 0 {
		fmt.Printf("Wildcard: lookups under %s go through RouteWise\n", strings.Join(status.WildcardDomains, ", "))
	}
	if status.WildcardError != "" {
		fmt.Printf("Wildcard: not active: %s\n", status.WildcardError)
	}
}

// pendingVPNs lists every detected-but-not-allowed tunnel. A helper that
// predates the list reports only the first, in pendingVpn.
func pendingVPNs(status api.StatusResult) []api.PendingVPN {
	if len(status.PendingVPNs) > 0 {
		return status.PendingVPNs
	}
	if status.PendingVPN != nil {
		return []api.PendingVPN{*status.PendingVPN}
	}
	return nil
}
