package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/spf13/cobra"
)

var (
	activityFollow bool
	activityLimit  int
)

var activityCmd = &cobra.Command{
	Use:   "activity",
	Short: "Show what went through the VPN and what went direct",
	Long: `Show recent routing activity: VPN connects and disconnects, routes added
and removed, refused addresses, and the DNS answers this Mac received with
each address marked VPN or DIRECT.

DNS answers served from the macOS cache, and lookups over DNS-over-HTTPS,
do not appear. The log lives in the helper's memory and is cleared when it
restarts.

Examples:
  routewise activity
  routewise activity -f`,
	RunE: runActivity,
}

func init() {
	activityCmd.Flags().BoolVarP(&activityFollow, "follow", "f", false, "keep printing new activity")
	activityCmd.Flags().IntVarP(&activityLimit, "limit", "n", 50, "how many recent events to show first")
	rootCmd.AddCommand(activityCmd)
}

func runActivity(cmd *cobra.Command, args []string) error {
	ctx := commandContext(cmd)
	params := api.ActivityParams{Limit: activityLimit}
	// step prints one page and moves params on; the first call also checks that
	// the helper is up.
	step := func(ctx context.Context) error {
		var result api.ActivityResult
		if err := requireHelper(ctx, "activity.list", params, &result); err != nil {
			return err
		}
		for _, e := range result.Events {
			fmt.Println(formatActivity(e))
		}
		// Long-poll: the helper answers the moment something new happens.
		params = api.ActivityParams{Since: result.Latest, WaitMs: followWaitMs}
		return nil
	}
	if !activityFollow {
		return step(ctx)
	}
	return followLoop(ctx, step)
}

func formatActivity(e activity.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %-13s", e.Time.Local().Format("15:04:05"), e.Kind)
	if e.Name != "" {
		b.WriteString(" " + e.Name)
	}
	for _, a := range e.Addresses {
		fmt.Fprintf(&b, "  %s=%s", a.IP, verdictLabel(a.Verdict == activity.ViaVPN))
	}
	if e.Interface != "" {
		b.WriteString("  [" + e.Interface + "]")
	}
	if e.Detail != "" {
		b.WriteString("  " + e.Detail)
	}
	return b.String()
}
