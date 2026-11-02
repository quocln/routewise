package outlinetunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// maxDynamicKeyBody bounds the response so a hostile or broken endpoint
	// cannot make the root helper buffer unbounded data.
	maxDynamicKeyBody = 64 << 10
)

// dynamicKeyTimeout caps the whole fetch. It is a variable so tests can
// shorten it.
var dynamicKeyTimeout = 10 * time.Second

// FetchDynamicKey resolves an `ssconf://` (or `https://`) dynamic access key
// URL to a Key. The body is either JSON (server, server_port, password,
// method, optional prefix) or a single `ss://` line. The URL itself is a
// secret, so no error ever contains it.
func FetchDynamicKey(ctx context.Context, client *http.Client, ssconf string) (Key, error) {
	target, err := dynamicKeyURL(ssconf)
	if err != nil {
		return Key{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	// Work on a copy so the caller's client is untouched, and refuse any
	// redirect that would leave HTTPS.
	c := *client
	prev := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("dynamic key redirected to a non-HTTPS URL")
		}
		if prev != nil {
			return prev(req, via)
		}
		if len(via) >= 10 {
			return errors.New("dynamic key redirected too many times")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, dynamicKeyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Key{}, errors.New("invalid dynamic key URL")
	}
	resp, err := c.Do(req)
	if err != nil {
		return Key{}, fmt.Errorf("fetch dynamic key: %w", stripURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Key{}, fmt.Errorf("fetch dynamic key: server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDynamicKeyBody+1))
	if err != nil {
		return Key{}, fmt.Errorf("read dynamic key: %w", stripURL(err))
	}
	if len(body) > maxDynamicKeyBody {
		return Key{}, fmt.Errorf("dynamic key response exceeds %d bytes", maxDynamicKeyBody)
	}
	return parseDynamicBody(body)
}

// dynamicKeyURL maps ssconf:// to https:// and rejects every other scheme, so
// the secret URL and the credentials it returns never travel in clear text.
func dynamicKeyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	var rest string
	switch {
	case len(raw) >= 9 && strings.EqualFold(raw[:9], "ssconf://"):
		rest = raw[9:]
	case len(raw) >= 8 && strings.EqualFold(raw[:8], "https://"):
		rest = raw[8:]
	default:
		return "", errors.New("dynamic key URL must use ssconf:// or https://")
	}
	u, err := url.Parse("https://" + rest)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid dynamic key URL")
	}
	// The fragment is client-side only (a label); never send it.
	u.Fragment = ""
	return u.String(), nil
}

// stripURL removes the request URL that net/http embeds in transport errors.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// dynamicKeyJSON mirrors the ssconf document. server_port is accepted as a
// number or a numeric string.
type dynamicKeyJSON struct {
	Server     string          `json:"server"`
	ServerPort json.RawMessage `json:"server_port"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	Prefix     string          `json:"prefix"`
}

func parseDynamicBody(body []byte) (Key, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return Key{}, errors.New("dynamic key response is empty")
	}
	if !strings.HasPrefix(trimmed, "{") {
		line, _, _ := strings.Cut(trimmed, "\n")
		return ParseAccessKey(line)
	}
	var d dynamicKeyJSON
	if err := json.Unmarshal([]byte(trimmed), &d); err != nil {
		return Key{}, errors.New("dynamic key response is not valid JSON")
	}
	port, err := parsePortJSON(d.ServerPort)
	if err != nil {
		return Key{}, err
	}
	k := Key{Method: strings.ToLower(d.Method), Password: d.Password, Host: d.Server, Port: port}
	if d.Prefix != "" {
		k.Prefix = prefixBytes(d.Prefix)
	}
	if err := k.validate(); err != nil {
		return Key{}, err
	}
	return k, nil
}

func parsePortJSON(raw json.RawMessage) (uint16, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("dynamic key server_port must be 1-65535")
	}
	return uint16(n), nil
}
