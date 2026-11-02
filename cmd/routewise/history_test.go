package main

import (
	"testing"
	"time"

	"github.com/quocln/routewise/internal/history"
)

func TestFormatAccessPrintsTheDocumentedColumns(t *testing.T) {
	at := time.Date(2026, 10, 28, 9, 5, 7, 0, time.Local)
	cases := []struct {
		e    history.Entry
		want string
	}{
		{history.Entry{Time: at, Verdict: "vpn", Name: "jira.corp.example.com", IP: "10.20.30.40", Port: 443, Proto: "tcp", Interface: "utun4", VPN: "WireGuard"},
			"10-28 09:05:07  vpn     jira.corp.example.com  10.20.30.40:443 tcp  utun4/WireGuard"},
		{history.Entry{Time: at, Verdict: "direct", IP: "93.184.216.34", Port: 443, Proto: "udp", Interface: "en0"},
			"10-28 09:05:07  direct  -  93.184.216.34:443 udp  en0"},
		{history.Entry{Time: at, Verdict: "other", Name: "x.example.com", IP: "2001:db8::1", Port: 22, Proto: "tcp", Interface: "utun2"},
			"10-28 09:05:07  other   x.example.com  [2001:db8::1]:22 tcp  utun2"},
	}
	for _, c := range cases {
		if got := formatAccess(c.e); got != c.want {
			t.Errorf("formatAccess =\n%q\nwant\n%q", got, c.want)
		}
	}
}

func TestParseSinceAcceptsHoursMinutesAndDays(t *testing.T) {
	good := map[string]time.Duration{
		"1h": time.Hour, "24h": 24 * time.Hour, "90m": 90 * time.Minute, "7d": 7 * 24 * time.Hour, "1d": 24 * time.Hour,
	}
	for in, want := range good {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("parseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "0d", "-1d", "1.5d", "abc", "-5h", "0s"} {
		if _, err := parseSince(in); err == nil {
			t.Errorf("parseSince(%q) must fail", in)
		}
	}
}

func TestBuildHistoryQueryFromFlags(t *testing.T) {
	reset := func() {
		historyLimit, historySince, historySearch, historyVPNOnly, historyDirectOnly = 50, "", "", false, false
	}
	defer reset()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	reset()
	historyLimit, historySince, historySearch, historyVPNOnly = 20, "2h", "corp", true
	q, err := buildHistoryQuery(now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Limit != 20 || q.Search != "corp" || q.Verdict != "vpn" || q.SinceMs != now.Add(-2*time.Hour).UnixMilli() || q.AfterID != nil {
		t.Fatalf("query = %+v", q)
	}

	reset()
	historyDirectOnly = true
	if q, _ := buildHistoryQuery(now); q.Verdict != "direct" {
		t.Errorf("--direct-only verdict = %q", q.Verdict)
	}

	reset()
	historyVPNOnly, historyDirectOnly = true, true
	if _, err := buildHistoryQuery(now); err == nil {
		t.Error("--vpn-only with --direct-only must be an error")
	}
	reset()
	historyLimit = 0
	if _, err := buildHistoryQuery(now); err == nil {
		t.Error("-n 0 must be an error")
	}
	reset()
	historySince = "soon"
	if _, err := buildHistoryQuery(now); err == nil {
		t.Error("a bad --since must be an error")
	}
}
