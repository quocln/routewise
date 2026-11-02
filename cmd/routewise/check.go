package main

import (
	"fmt"
	"strings"

	"github.com/quocln/routewise/internal/api"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check <host>",
	Short: "Show whether traffic to a host goes through the VPN",
	Long: `Resolve a host (or take an IP or URL) the way any app on this Mac would,
and ask the kernel which interface traffic to each address leaves through.

Examples:
  routewise check jira.corp.example.com
  routewise check https://grafana.corp.example.com/d/abc
  routewise check 10.20.30.40`,
	Args: cobra.ExactArgs(1),
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	var result api.HostCheck
	if err := requireHelper(commandContext(cmd), "routes.check", api.CheckHostParams{Host: args[0]}, &result); err != nil {
		return err
	}

	fmt.Printf("Host:    %s\n", result.Host)
	if len(result.MatchedPatterns) > 0 {
		fmt.Printf("Matches: %s\n", strings.Join(result.MatchedPatterns, ", "))
	} else {
		fmt.Println("Matches: no configured domain")
	}
	if result.VPNInterface == "" {
		fmt.Println("VPN:     not managed right now, so everything goes direct")
	}
	fmt.Println()
	for _, a := range result.Addresses {
		line := fmt.Sprintf("  %-7s %-40s", verdictLabel(a.Verdict == "vpn"), a.IP)
		if a.Interface != "" {
			line += " via " + a.Interface
		}
		if a.Gateway != "" {
			line += " (" + a.Gateway + ")"
		}
		if a.RoutedFor != "" {
			line += "  routed for " + a.RoutedFor
		}
		if a.Note != "" {
			line += "  " + a.Note
		}
		fmt.Println(line)
	}
	return nil
}
