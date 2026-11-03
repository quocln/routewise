// Package proxyclient opens flows through a SOCKS5 or HTTP proxy, for the tunnel a
// built-in proxy profile runs. Neither protocol encrypts the connection to the proxy, so
// the username and password are protected only as far as the network to it is.
package proxyclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// maxCredentialLen is RFC 1929's limit on a username and on a password.
const maxCredentialLen = 255

// Config is a parsed proxy address. Username and Password are both set or both empty.
type Config struct {
	Host     string
	Port     uint16
	Username string
	Password string
}

// HostPort is the proxy's host and port, which holds no secret.
func (c Config) HostPort() string { return net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))) }

// Protocol says which kind of proxy an address may name.
type Protocol string

// The proxies this package speaks.
const (
	SOCKS5 Protocol = "socks5"
	HTTP   Protocol = "http"
)

// schemes lists what an address of each protocol may start with. socks5h:// means the
// same as socks5://, since the tunnel only ever hands a proxy an address.
var schemes = map[Protocol][]string{
	SOCKS5: {"socks5", "socks5h"},
	HTTP:   {"http"},
}

// ParseURL reads scheme://[username:password@]host:port, with the username and
// password percent-encoded. Its errors never contain the text they were given: that
// text can hold the password.
func ParseURL(protocol Protocol, text string) (Config, error) {
	text = strings.TrimSpace(text)
	u, err := url.Parse(text)
	if err != nil {
		return Config{}, errors.New("the proxy address is not a valid URL")
	}
	if !slices.Contains(schemes[protocol], strings.ToLower(u.Scheme)) {
		return Config{}, fmt.Errorf("the proxy address must start with %s://", protocol)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("the proxy address must be only %s://[username:password@]host:port", protocol)
	}
	host := u.Hostname()
	if host == "" {
		return Config{}, errors.New("the proxy address has no host")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return Config{}, errors.New("the proxy address needs a port between 1 and 65535")
	}
	c := Config{Host: host, Port: uint16(port)}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	if (c.Username == "") != (c.Password == "") {
		return Config{}, errors.New("the proxy needs both a username and a password, or neither")
	}
	// Basic authentication joins the two with a colon, so a colon cannot be in the name.
	if protocol == HTTP && strings.Contains(c.Username, ":") {
		return Config{}, errors.New("an HTTP proxy username cannot contain a colon")
	}
	if len(c.Username) > maxCredentialLen || len(c.Password) > maxCredentialLen {
		return Config{}, fmt.Errorf("a proxy username or password can be at most %d bytes", maxCredentialLen)
	}
	return c, nil
}

// Resolver resolves the proxy's host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve returns the proxy's address, IPv4 preferred. IP literals skip the resolver.
// The tunnel keeps connecting to this address, so no lookup can recurse into it.
func (c Config) Resolve(ctx context.Context, r Resolver) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(c.Host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), c.Port), nil
	}
	addrs, err := r.LookupNetIP(ctx, "ip", c.Host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve proxy %q: %w", c.Host, err)
	}
	a, ok := tunnelnet.PreferIPv4(addrs)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("resolve proxy %q: no addresses", c.Host)
	}
	return netip.AddrPortFrom(a, c.Port), nil
}
