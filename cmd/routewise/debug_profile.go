package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/spf13/cobra"
)

var (
	profileSeconds int
	profileOutput  string
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Tools for diagnosing the helper",
}

var debugProfileCmd = &cobra.Command{
	Use:   "profile {cpu|heap|mutex}",
	Short: "Record a runtime profile of the running helper",
	Long: `Record a runtime profile of the running helper and write it to a file, for
"go tool pprof". It holds function names and counts, never the contents of
memory. The helper keeps running and nothing needs a restart.

cpu and mutex record for --seconds; heap is a snapshot.`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{string(api.ProfileCPU), string(api.ProfileHeap), string(api.ProfileMutex)},
	RunE: func(_ *cobra.Command, args []string) error {
		output := profileOutput
		if output == "" {
			output = args[0] + ".pprof"
		}
		params := api.ProfileParams{
			Kind:    api.ProfileKind(args[0]),
			Seconds: profileSeconds,
			// The helper holds the answer for this long on purpose.
			WaitMs: profileSeconds * 1000,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(profileSeconds)*time.Second+time.Minute)
		defer cancel()
		var result api.ProfileResult
		if err := requireHelper(ctx, api.MethodDebugProfile, params, &result); err != nil {
			return err
		}
		if err := os.WriteFile(output, result.Data, 0o600); err != nil {
			return fmt.Errorf("write the profile: %w", err)
		}
		fmt.Printf("Wrote %s (%d bytes). Read it with: go tool pprof -top %s\n", output, len(result.Data), output)
		return nil
	},
}

func init() {
	debugProfileCmd.Flags().IntVar(&profileSeconds, "seconds", 30, "how long to record")
	debugProfileCmd.Flags().StringVarP(&profileOutput, "output", "o", "", "file to write (default <kind>.pprof)")
	debugCmd.AddCommand(debugProfileCmd)
	rootCmd.AddCommand(debugCmd)
}
