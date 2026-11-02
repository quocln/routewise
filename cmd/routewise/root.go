package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/platform"
)

var (
	cfgFile        string
	verbose        bool
	insecureConfig bool

	rootCmd = &cobra.Command{
		Use:   "routewise",
		Short: "Smart VPN routing daemon for macOS",
		Long: `A daemon that selectively routes traffic through a full-tunnel VPN
(AWS Client VPN, OpenVPN, WireGuard) for specific domains while keeping
other traffic direct.

Features:
  - Domain-based routing (supports wildcards)
  - DNS resolution with caching
  - Automatic VPN detection
  - Inverted split tunnel (replaces VPN default route)

Usage:
  sudo routewise start      Start the daemon
  routewise status          Check daemon/VPN status
  routewise list-routes     Show active routes
  routewise add-domain      Add domain pattern to config
  sudo routewise stop       Stop the daemon`,
	}
)

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default %s)", config.DefaultConfigPath))
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"verbose output")
	rootCmd.PersistentFlags().BoolVar(&insecureConfig, "insecure-config", false,
		"skip config file security validation (not recommended)")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Primary: system config path (works when running as launchd daemon)
		viper.AddConfigPath(platform.ConfigDir())
		// Fallback: user home directory (if available and not running as root daemon)
		// Note: os.UserHomeDir() returns error when $HOME is not set (e.g., LaunchDaemon)
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			viper.AddConfigPath(filepath.Join(home, ".routewise"))
		}
		viper.AddConfigPath("/etc/routewise")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}
	viper.AutomaticEnv()
	_ = viper.ReadInConfig() // Ignore error; will use defaults
}

// getConfigPath returns the config file path being used.
func getConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	if viper.ConfigFileUsed() != "" {
		return viper.ConfigFileUsed()
	}
	return config.DefaultConfigPath
}
