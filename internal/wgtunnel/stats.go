package wgtunnel

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PeerStats is the live state of one peer as reported by the device.
type PeerStats struct {
	PublicKey Key
	// Endpoint is the address actually in use; it can differ from the
	// configured one after the remote roams. Invalid when none is known yet.
	Endpoint netip.AddrPort
	// LastHandshake is zero when no handshake has completed.
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// Stats is the live state of the tunnel.
type Stats struct {
	Peers []PeerStats
}

// ParseStats parses the text returned by Device.IpcGet.
func ParseStats(text string) (Stats, error) {
	var st Stats
	var cur *PeerStats
	var hsSec, hsNsec int64

	flush := func() {
		if cur == nil {
			return
		}
		if hsSec != 0 || hsNsec != 0 {
			cur.LastHandshake = time.Unix(hsSec, hsNsec)
		}
		st.Peers = append(st.Peers, *cur)
		cur, hsSec, hsNsec = nil, 0, 0
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Stats{}, fmt.Errorf("malformed device line %q", line)
		}
		if k == "public_key" {
			flush()
			key, err := parseHexKey(v)
			if err != nil {
				return Stats{}, fmt.Errorf("public_key: %w", err)
			}
			cur = &PeerStats{PublicKey: key}
			continue
		}
		if cur == nil {
			continue // interface-level key (private_key, listen_port, ...)
		}
		var err error
		switch k {
		case "endpoint":
			// An unparsable endpoint (e.g. "(none)") just means unknown.
			if ap, perr := netip.ParseAddrPort(v); perr == nil {
				cur.Endpoint = ap
			}
		case "last_handshake_time_sec":
			hsSec, err = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, err = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			cur.RxBytes, err = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			cur.TxBytes, err = strconv.ParseUint(v, 10, 64)
		}
		if err != nil {
			return Stats{}, fmt.Errorf("%s: %w", k, err)
		}
	}
	flush()
	return st, nil
}
