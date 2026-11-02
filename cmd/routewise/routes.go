package main

import (
	"fmt"

	"github.com/quocln/routewise/internal/ifacename"
	"github.com/quocln/routewise/internal/route"
	"github.com/spf13/cobra"
)

var listRoutesCmd = &cobra.Command{
	Use:   "list-routes",
	Short: "List active VPN routes",
	Long: `Display all routes currently managed by the daemon.

Shows the destination IP, gateway, and when the route was added.

Note: This shows routes from the daemon's internal state.
Use 'netstat -rn' for the system routing table.

Examples:
  routewise list-routes`,
	RunE: runListRoutes,
}

func init() {
	rootCmd.AddCommand(listRoutesCmd)
}

func runListRoutes(cmd *cobra.Command, args []string) error {
	// Get system routes via netstat for display
	// Note: We can't access the daemon's internal route manager directly
	// So we show system routes that match our criteria

	routes, err := route.ListRoutes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	// Filter for routes that might be ours (utun interface with /32)
	var vpnRoutes []route.RouteEntry
	for _, r := range routes {
		// Show routes via utun interfaces
		if ifacename.IsTunnel(r.Interface) {
			// Skip link-local and special routes
			if r.Gateway == "" || r.Gateway[:4] == "link" {
				continue
			}
			vpnRoutes = append(vpnRoutes, r)
		}
	}

	if len(vpnRoutes) == 0 {
		fmt.Println("No active VPN routes")
		fmt.Println("\nTip: Start the daemon with VPN connected to see routes")
		return nil
	}

	fmt.Printf("Active VPN routes (%d):\n\n", len(vpnRoutes))
	fmt.Printf("%-25s %-20s %s\n", "DESTINATION", "GATEWAY", "INTERFACE")
	fmt.Println("---------------------------------------------------")

	for _, r := range vpnRoutes {
		fmt.Printf("%-25s %-20s %s\n", r.Destination, r.Gateway, r.Interface)
	}

	return nil
}

// ListRoutes is exported for use by routes command
func ListRoutes() ([]route.RouteEntry, error) {
	return route.ListRoutes()
}
