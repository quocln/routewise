package main

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/history"
	"github.com/spf13/cobra"
)

var (
	historyLimit      int
	historySince      string
	historySearch     string
	historyVPNOnly    bool
	historyDirectOnly bool
	historyFollow     bool
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show which hosts this Mac connected to, and when",
	Long: `Show the access history: every new outbound connection (a TCP SYN, or the
first QUIC packet of a UDP flow) with its time, the domain it was resolved
from, the address and port, the protocol, and the network interface. The
verdict says whether it went through a managed VPN, directly, or through
another tunnel RouteWise does not manage.

The domain comes from recent DNS answers this Mac received; it is blank when
the address was never resolved while RouteWise was watching. Reading the
history needs the console user, like 'routewise activity'.

Examples:
  routewise history
  routewise history --since 24h --search example.com
  routewise history --vpn-only -n 200
  routewise history -f`,
	Args: cobra.NoArgs,
	RunE: runHistory,
}

func init() {
	f := historyCmd.Flags()
	f.IntVarP(&historyLimit, "limit", "n", 50, "how many recent connections to show")
	f.StringVar(&historySince, "since", "", "only connections newer than this (for example 1h, 24h, 7d)")
	f.StringVar(&historySearch, "search", "", "only connections whose domain or address contains this text")
	f.BoolVar(&historyVPNOnly, "vpn-only", false, "only connections through a managed VPN")
	f.BoolVar(&historyDirectOnly, "direct-only", false, "only connections that went direct")
	f.BoolVarP(&historyFollow, "follow", "f", false, "keep printing new connections")
	rootCmd.AddCommand(historyCmd)
}

func runHistory(cmd *cobra.Command, args []string) error {
	query, err := buildHistoryQuery(time.Now())
	if err != nil {
		return err
	}
	ctx := commandContext(cmd)

	var result api.AccessListResult
	if err := requireHelper(ctx, "access.list", query, &result); err != nil {
		return err
	}
	// The helper answers newest first; print oldest first so the latest line
	// is last, where -f continues.
	slices.Reverse(result.Entries)
	for _, e := range result.Entries {
		fmt.Println(formatAccess(e))
	}
	if !historyFollow {
		return nil
	}

	latest := result.LatestID
	return followLoop(ctx, func(ctx context.Context) error {
		follow := query
		follow.AfterID, follow.SinceMs, follow.Limit, follow.WaitMs = &latest, 0, history.DefaultLimit, followWaitMs
		var next api.AccessListResult
		if err := requireHelper(ctx, "access.list", follow, &next); err != nil {
			return err
		}
		for _, e := range next.Entries {
			fmt.Println(formatAccess(e))
		}
		latest = next.LatestID
		return nil
	})
}

// buildHistoryQuery turns the command-line flags into the first query.
func buildHistoryQuery(now time.Time) (api.AccessListParams, error) {
	if historyVPNOnly && historyDirectOnly {
		return api.AccessListParams{}, fmt.Errorf("--vpn-only and --direct-only cannot be combined")
	}
	if historyLimit < 1 {
		return api.AccessListParams{}, fmt.Errorf("-n must be at least 1")
	}
	q := api.AccessListParams{Limit: historyLimit, Search: historySearch}
	switch {
	case historyVPNOnly:
		q.Verdict = history.VerdictVPN
	case historyDirectOnly:
		q.Verdict = history.VerdictDirect
	}
	if historySince != "" {
		d, err := parseSince(historySince)
		if err != nil {
			return api.AccessListParams{}, err
		}
		q.SinceMs = now.Add(-d).UnixMilli()
	}
	return q, nil
}

// parseSince reads a window such as 90m, 24h or 7d.
func parseSince(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("--since %q: use a positive number of days such as 7d", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--since %q: use a duration such as 90m, 24h or 7d", s)
	}
	return d, nil
}

// formatAccess renders one connection as
// "time  verdict  name  ip:port proto  iface/vpn".
func formatAccess(e history.Entry) string {
	name := e.Name
	if name == "" {
		name = "-"
	}
	where := e.Interface
	if e.VPN != "" {
		where += "/" + e.VPN
	}
	return fmt.Sprintf("%s  %-6s  %s  %s %s  %s",
		e.Time.Local().Format("01-02 15:04:05"), e.Verdict, name,
		hostPort(e.IP, e.Port), e.Proto, where)
}

// hostPort joins an address and a port, bracketing an IPv6 address.
func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return ip + ":" + strconv.Itoa(port)
}
