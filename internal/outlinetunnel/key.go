// Package outlinetunnel runs an Outline (Shadowsocks) client inside the
// privileged helper: it owns a utun, turns the IP packets routed into it back
// into TCP and UDP flows with a pure-Go gVisor stack, and sends those flows out
// through a Shadowsocks server. It never adds routes; routing is the caller's job.
package outlinetunnel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.getoutline.org/sdk/transport/shadowsocks"
)

// Cipher names as they appear in access keys. They map to the AEAD ciphers the
// Shadowsocks SDK implements; anything else is refused up front so a profile
// fails at import time instead of at the first connection.
const (
	CipherChaCha20 = "chacha20-ietf-poly1305"
	CipherAES128   = "aes-128-gcm"
	CipherAES192   = "aes-192-gcm"
	CipherAES256   = "aes-256-gcm"
)

// sdkCipher maps an access-key cipher name to the SDK constant.
var sdkCipher = map[string]string{
	CipherChaCha20: shadowsocks.CHACHA20IETFPOLY1305,
	CipherAES128:   shadowsocks.AES128GCM,
	CipherAES192:   shadowsocks.AES192GCM,
	CipherAES256:   shadowsocks.AES256GCM,
}

// Key is a parsed Outline access key.
type Key struct {
	// Method is one of the Cipher* names.
	Method string
	// Password is the Shadowsocks secret. It must never be logged or returned
	// over RPC; use Redacted for anything user-visible.
	Password string
	// Host is a DNS name or an IP literal (without brackets).
	Host string
	Port uint16
	// Prefix is the optional disguise prefix written before the salt.
	Prefix []byte
	// Tag is the human label from the URL fragment.
	Tag string
}

// Redacted returns a copy with the password blanked, safe to log or return.
func (k Key) Redacted() Key {
	k.Password = ""
	return k
}

// Addr is the host:port of the Shadowsocks server as written in the key.
func (k Key) Addr() string {
	return net.JoinHostPort(k.Host, strconv.Itoa(int(k.Port)))
}

// String never reveals the password, so a stray %v in a log line is harmless.
func (k Key) String() string {
	return fmt.Sprintf("ss://%s:***@%s", k.Method, k.Addr())
}

// encryptionKey derives the SDK key from the method and password.
func (k Key) encryptionKey() (*shadowsocks.EncryptionKey, error) {
	name, ok := sdkCipher[k.Method]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher %q", k.Method)
	}
	ek, err := shadowsocks.NewEncryptionKey(name, k.Password)
	if err != nil {
		// The SDK error does not echo the password, but wrap generically anyway.
		return nil, errors.New("invalid shadowsocks key material")
	}
	return ek, nil
}

// validate checks the fields shared by every key source. Errors name the field,
// never the value of the password.
func (k Key) validate() error {
	if _, ok := sdkCipher[k.Method]; !ok {
		return fmt.Errorf("unsupported cipher %q (supported: %s, %s, %s, %s)",
			k.Method, CipherChaCha20, CipherAES128, CipherAES192, CipherAES256)
	}
	if k.Password == "" {
		return errors.New("access key has an empty password")
	}
	if k.Port == 0 {
		return errors.New("access key port must be 1-65535")
	}
	if !validHost(k.Host) {
		return fmt.Errorf("invalid server host %q", k.Host)
	}
	return nil
}

// validHost accepts an IP literal or an RFC 1123-ish host name. Underscores are
// tolerated because real deployments use them.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			ok := c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !ok {
				return false
			}
		}
	}
	return true
}

// ParseAccessKey parses an `ss://` access key: SIP002
// (`ss://BASE64URL(method:password)@host:port[/][?prefix=..][#tag]`, with the
// userinfo optionally percent-encoded plain text) or the legacy
// `ss://BASE64(method:password@host:port)#tag` form. Plugins are unsupported.
func ParseAccessKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if len(s) < 5 || !strings.EqualFold(s[:5], "ss://") {
		return Key{}, errors.New("access key must start with ss://")
	}
	rest := s[5:]

	var tag string
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		t, err := url.PathUnescape(rest[i+1:])
		if err != nil {
			return Key{}, errors.New("access key tag is not valid percent-encoding")
		}
		tag, rest = t, rest[:i]
	}
	var rawQuery string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rawQuery, rest = rest[i+1:], rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" || strings.ContainsAny(rest, "/ ") {
		return Key{}, errors.New("access key has an unexpected path")
	}

	var k Key
	var err error
	if strings.Contains(rest, "@") {
		k, err = parseSIP002(rest)
	} else {
		k, err = parseLegacy(rest)
	}
	if err != nil {
		return Key{}, err
	}
	k.Tag = tag

	if rawQuery != "" {
		q, qerr := url.ParseQuery(rawQuery)
		if qerr != nil {
			return Key{}, errors.New("access key query is not valid")
		}
		if q.Has("plugin") {
			return Key{}, errors.New("shadowsocks plugins (plugin=) are not supported")
		}
		if p := q.Get("prefix"); p != "" {
			k.Prefix = prefixBytes(p)
		}
	}
	if err := k.validate(); err != nil {
		return Key{}, err
	}
	return k, nil
}

// parseSIP002 handles `userinfo@host:port`. The password may itself contain
// '@' only when percent-encoded, so the last raw '@' is the separator.
func parseSIP002(authority string) (Key, error) {
	at := strings.LastIndexByte(authority, '@')
	userinfo, hostport := authority[:at], authority[at+1:]

	var creds string
	if strings.ContainsAny(userinfo, ":%") {
		// Plain method:password, percent-encoded.
		u, err := url.PathUnescape(userinfo)
		if err != nil {
			return Key{}, errors.New("access key userinfo is not valid percent-encoding")
		}
		creds = u
	} else {
		b, err := decodeBase64(userinfo)
		if err != nil {
			return Key{}, errors.New("access key userinfo is not valid base64")
		}
		creds = string(b)
	}
	method, password, ok := strings.Cut(creds, ":")
	if !ok {
		return Key{}, errors.New("access key userinfo must be method:password")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return Key{}, err
	}
	return Key{Method: strings.ToLower(method), Password: password, Host: host, Port: port}, nil
}

// parseLegacy handles `BASE64(method:password@host:port)`.
func parseLegacy(encoded string) (Key, error) {
	b, err := decodeBase64(encoded)
	if err != nil {
		return Key{}, errors.New("access key is not valid base64")
	}
	decoded := string(b)
	at := strings.LastIndexByte(decoded, '@')
	if at < 0 {
		return Key{}, errors.New("legacy access key must decode to method:password@host:port")
	}
	method, password, ok := strings.Cut(decoded[:at], ":")
	if !ok {
		return Key{}, errors.New("legacy access key must decode to method:password@host:port")
	}
	host, port, err := splitHostPort(decoded[at+1:])
	if err != nil {
		return Key{}, err
	}
	return Key{Method: strings.ToLower(method), Password: password, Host: host, Port: port}, nil
}

func splitHostPort(hostport string) (string, uint16, error) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, errors.New("access key must have host:port")
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, errors.New("access key port must be 1-65535")
	}
	return host, uint16(n), nil
}

// decodeBase64 accepts standard and URL alphabets, padded or not, as keys in
// the wild use all four.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// prefixBytes converts the decoded prefix string to wire bytes. Outline clients
// treat each character as one byte (Latin-1), so "%C2%80" and "%80" both mean
// 0x80; text above U+00FF is kept as its UTF-8 bytes.
func prefixBytes(p string) []byte {
	if utf8.ValidString(p) {
		out := make([]byte, 0, len(p))
		for _, r := range p {
			if r > 0xFF {
				return []byte(p)
			}
			out = append(out, byte(r))
		}
		return out
	}
	return []byte(p)
}
