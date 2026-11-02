package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Export or import the routing configuration",
	Long: `Export or import the routing configuration as JSON: domain lists, allowed
VPN clients with their own domains, DNS settings, and routing mode.
Machine-specific daemon settings (pid file, log file, poll interval) are
not included.`,
}

var configExportCmd = &cobra.Command{
	Use:   "export [file]",
	Short: "Write the routing configuration to a file, or to stdout",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runConfigExport,
}

var configImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Replace the routing configuration with an exported file",
	Long: `Replace the routing configuration with an exported file. The file is
checked completely before anything changes. With the helper running, the
change applies at once; DNS servers, cache TTL, and routing mode take effect
after "sudo routewise restart".`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigImport,
}

func init() {
	configCmd.AddCommand(configExportCmd, configImportCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigExport(cmd *cobra.Command, args []string) error {
	var export config.Export
	running, err := callHelper(commandContext(cmd), "config.export", nil, &export)
	if running {
		if err != nil {
			return err
		}
	} else {
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		export = config.NewExport(cfg, time.Now())
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(args) == 0 {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(args[0], data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", args[0], err)
	}
	fmt.Fprintf(os.Stderr, "Exported %d domain patterns and %d VPN clients to %s\n",
		countPatterns(export), len(export.VPNs), args[0])
	return nil
}

func runConfigImport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	export, err := config.ParseExport(data)
	if err != nil {
		return err
	}

	var result api.ImportConfigResult
	viaHelper, err := rpcOrDirect(commandContext(cmd), "config.import", api.ImportConfigParams{Config: export}, &result)
	if err != nil {
		return err
	}
	if viaHelper {
		fmt.Printf("Imported %d domain patterns and %d VPN clients.\n", countPatterns(export), len(export.VPNs))
		if result.RestartRequired {
			fmt.Println("DNS servers, cache TTL, or routing mode changed: run `sudo routewise restart` to apply them.")
		}
		return nil
	}

	// An import replaces the stored config, so a config that could not be read
	// must stop it rather than be treated as empty.
	current, err := loadConfigForUpdate()
	if err != nil {
		return err
	}
	next, err := export.Apply(current)
	if err != nil {
		return err
	}
	if err := saveConfig(next); err != nil {
		return fmt.Errorf("save config (run with sudo): %w", err)
	}
	fmt.Printf("Imported %d domain patterns and %d VPN clients. Start the helper to apply them.\n",
		countPatterns(export), len(export.VPNs))
	return nil
}

func countPatterns(e config.Export) int {
	n := len(e.Domains)
	for _, v := range e.VPNs {
		n += len(v.Domains)
	}
	return n
}
