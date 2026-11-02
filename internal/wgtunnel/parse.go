package wgtunnel

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// maxConfigBytes bounds the text Parse accepts; real profiles are well under
// 4 KiB, so this only stops pathological input at the RPC boundary.
const maxConfigBytes = 256 * 1024

// ignoredInterfaceKeys are wg-quick features that run commands or alter
// routing. They are recorded as warnings and never acted on.
var ignoredInterfaceKeys = map[string]bool{
	"table": true, "preup": true, "postup": true,
	"predown": true, "postdown": true, "saveconfig": true, "fwmark": true,
}

// Parse reads a wg-quick .conf file. Errors name the offending line number and
// never echo key material.
func Parse(text string) (Config, error) {
	var cfg Config
	if len(text) > maxConfigBytes {
		return cfg, fmt.Errorf("config is larger than %d bytes", maxConfigBytes)
	}

	const (
		secNone = iota
		secInterface
		secPeer
	)
	section := secNone
	interfaces := 0
	var peer *Peer
	peerLine := 0

	// finishPeer validates the section just closed.
	finishPeer := func() error {
		if peer == nil {
			return nil
		}
		if peer.PublicKey.IsZero() {
			return fmt.Errorf("line %d: [Peer] is missing PublicKey", peerLine)
		}
		cfg.Peers = append(cfg.Peers, *peer)
		peer = nil
		return nil
	}

	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		line := raw
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if err := finishPeer(); err != nil {
				return Config{}, err
			}
			switch strings.ToLower(line) {
			case "[interface]":
				interfaces++
				if interfaces > 1 {
					return Config{}, fmt.Errorf("line %d: more than one [Interface] section", lineNo)
				}
				section = secInterface
			case "[peer]":
				section = secPeer
				peer = &Peer{}
				peerLine = lineNo
			default:
				return Config{}, fmt.Errorf("line %d: unknown section %q", lineNo, line)
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		var err error
		switch section {
		case secNone:
			err = fmt.Errorf("key outside any section")
		case secInterface:
			err = parseInterfaceKey(&cfg, key, val)
		case secPeer:
			err = parsePeerKey(&cfg, peer, key, val)
		}
		if err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if section == secInterface && ignoredInterfaceKeys[key] {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("line %d: ignored %s (not supported)", lineNo, key))
		}
	}
	if err := finishPeer(); err != nil {
		return Config{}, err
	}

	if interfaces != 1 {
		return Config{}, fmt.Errorf("config must contain exactly one [Interface] section")
	}
	if cfg.PrivateKey.IsZero() {
		return Config{}, fmt.Errorf("[Interface] is missing PrivateKey")
	}
	if len(cfg.IPv4Addresses()) == 0 {
		return Config{}, fmt.Errorf("[Interface] needs at least one IPv4 Address")
	}
	if len(cfg.Peers) == 0 {
		return Config{}, fmt.Errorf("config must contain at least one [Peer]")
	}
	return cfg, nil
}

func parseInterfaceKey(cfg *Config, key, val string) error {
	switch key {
	case "privatekey":
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PrivateKey: %w", err)
		}
		cfg.PrivateKey = k
	case "address":
		for _, item := range splitList(val) {
			p, err := parsePrefixOrHost(item)
			if err != nil {
				return fmt.Errorf("Address %q: %w", item, err)
			}
			cfg.Addresses = append(cfg.Addresses, p)
		}
	case "dns":
		for _, item := range splitList(val) {
			if a, err := netip.ParseAddr(item); err == nil {
				cfg.DNS = append(cfg.DNS, a)
			} else {
				// wg-quick treats non-IP entries as resolv.conf search domains.
				cfg.DNSSearch = append(cfg.DNSSearch, item)
			}
		}
	case "mtu":
		n, err := strconv.Atoi(val)
		if err != nil || n < 576 || n > 65535 {
			return fmt.Errorf("MTU must be an integer between 576 and 65535")
		}
		cfg.MTU = n
	case "listenport":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("ListenPort must be an integer between 0 and 65535")
		}
		cfg.ListenPort = n
	default:
		if !ignoredInterfaceKeys[key] {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("ignored unknown [Interface] key %q", key))
		}
	}
	return nil
}

func parsePeerKey(cfg *Config, p *Peer, key, val string) error {
	switch key {
	case "publickey":
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PublicKey: %w", err)
		}
		p.PublicKey = k
	case "presharedkey":
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PresharedKey: %w", err)
		}
		p.PresharedKey = k
	case "endpoint":
		host, portStr, err := net.SplitHostPort(val)
		if err != nil || host == "" {
			return fmt.Errorf("Endpoint %q must be host:port", val)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("Endpoint port must be between 1 and 65535")
		}
		p.Endpoint = Endpoint{Host: host, Port: uint16(port)}
	case "allowedips":
		for _, item := range splitList(val) {
			pfx, err := parsePrefixOrHost(item)
			if err != nil {
				return fmt.Errorf("AllowedIPs %q: %w", item, err)
			}
			p.AllowedIPs = append(p.AllowedIPs, pfx)
		}
	case "persistentkeepalive":
		if strings.EqualFold(val, "off") {
			p.PersistentKeepalive = 0
			return nil
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("PersistentKeepalive must be \"off\" or an integer between 0 and 65535")
		}
		p.PersistentKeepalive = n
	default:
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("ignored unknown [Peer] key %q", key))
	}
	return nil
}

// splitList splits a comma-separated value, dropping empty items.
func splitList(val string) []string {
	var out []string
	for _, item := range strings.Split(val, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parsePrefixOrHost accepts "addr/len" or a bare address (treated as a host
// route, like wg-quick).
func parsePrefixOrHost(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
