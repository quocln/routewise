package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

var addDomainCmd = &cobra.Command{
	Use:   "add-domain <pattern>",
	Short: "Add a domain pattern, IPv4 address, or IPv4 CIDR to route via VPN",
	Long: `Add a domain pattern, an IPv4 address, or an IPv4 CIDR to the configuration.

Patterns:
  - Exact match: "example.com"
  - Wildcard label: "*.example.com" matches api.example.com, not example.com
    or a.b.example.com
  - Partial label: "qa*.example.com" matches qa1.example.com, qa-api.example.com

A wildcard may only appear once, in the first label. Wildcard names are
routed as they are looked up, while the VPN is connected.

An IPv4 address ("10.20.30.40") is routed as a single host. An IPv4 CIDR
("10.20.0.0/16", no shorter than /8) is routed as a network. IPv6 is not
supported, and loopback, link-local, multicast and 0.0.0.0/8 ranges are
rejected. A CIDR that contains the LAN gateway or overlaps a directly connected
network is refused when routes sync.

Examples:
  routewise add-domain "api.example.com"
  routewise add-domain "*.example.com"
  routewise add-domain "qa*.staging.example.com"
  routewise add-domain 10.20.30.40
  routewise add-domain 10.20.0.0/16`,
	Args: cobra.ExactArgs(1),
	RunE: runAddDomain,
}

var removeDomainCmd = &cobra.Command{
	Use:   "remove-domain <pattern>",
	Short: "Remove a domain pattern from config",
	Long: `Remove a domain pattern from the configuration.

The pattern must match exactly as it was added.

Examples:
  routewise remove-domain "api.example.com"
  routewise remove-domain "*.example.com"`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoveDomain,
}

var listDomainsCmd = &cobra.Command{
	Use:   "list-domains",
	Short: "List configured domain patterns",
	Long: `Display all domain patterns currently configured for VPN routing.

Examples:
  routewise list-domains`,
	RunE: runListDomains,
}

func init() {
	rootCmd.AddCommand(addDomainCmd)
	rootCmd.AddCommand(removeDomainCmd)
	rootCmd.AddCommand(listDomainsCmd)
}

func runAddDomain(cmd *cobra.Command, args []string) error {
	if _, err := config.ParseEntry(args[0]); err != nil {
		return fmt.Errorf("invalid entry %q: %w", args[0], err)
	}
	// An IP or CIDR is stored in canonical form (10.20.5.1/16 as 10.20.0.0/16).
	pattern := config.NormalizeEntry(args[0])

	viaHelper, err := rpcOrDirect(commandContext(cmd), "domains.add", api.AddDomainParams{Pattern: pattern}, nil)
	if err != nil {
		return err
	}
	if viaHelper {
		fmt.Printf("Added domain pattern: %s\n", pattern)
		return nil
	}

	// Defaults are used only when nothing has ever been stored; a failed load
	// is an error, never a reason to overwrite the stored config.
	cfg, err := loadConfigForUpdate()
	if err != nil {
		return err
	}

	for _, d := range cfg.Domains {
		if d.Pattern == pattern {
			fmt.Printf("Pattern already exists: %s\n", pattern)
			return nil
		}
	}

	cfg.Domains = config.NormalizeDomains(append(cfg.Domains, config.DomainRule{Pattern: pattern}))
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Added domain pattern: %s\n", pattern)
	fmt.Println("Start the daemon to apply changes: sudo routewise start")

	return nil
}

func runRemoveDomain(cmd *cobra.Command, args []string) error {
	pattern := config.NormalizeEntry(args[0])

	viaHelper, err := rpcOrDirect(commandContext(cmd), "domains.remove", api.RemoveDomainParams{Pattern: pattern}, nil)
	if err != nil {
		return err
	}
	if viaHelper {
		fmt.Printf("Removed domain pattern: %s\n", pattern)
		return nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	filtered := make([]config.DomainRule, 0, len(cfg.Domains))
	found := false
	for _, d := range cfg.Domains {
		if d.Pattern == pattern {
			found = true
			continue
		}
		filtered = append(filtered, d)
	}

	if !found {
		fmt.Printf("Pattern not found: %s\n", pattern)
		return nil
	}

	cfg.Domains = filtered
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := saveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Removed domain pattern: %s\n", pattern)
	fmt.Println("Start the daemon to apply changes")

	return nil
}

func runListDomains(cmd *cobra.Command, args []string) error {
	patterns, err := configuredDomains(commandContext(cmd))
	if err != nil {
		return err
	}

	if len(patterns) == 0 {
		fmt.Println("No domain patterns configured")
		return nil
	}

	fmt.Printf("Configured domain patterns (%d):\n", len(patterns))
	for _, p := range patterns {
		fmt.Printf("  %s\n", p)
	}

	return nil
}

// configuredDomains reads the live list from the helper when one is running so
// the CLI never reports a stale file.
func configuredDomains(ctx context.Context) ([]string, error) {
	var domains []api.Domain
	running, err := callHelper(ctx, "domains.list", nil, &domains)
	if running {
		if err != nil {
			return nil, err
		}
		patterns := make([]string, 0, len(domains))
		for _, d := range domains {
			patterns = append(patterns, d.Pattern)
		}
		return patterns, nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	patterns := make([]string, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		patterns = append(patterns, d.Pattern)
	}
	return patterns, nil
}
