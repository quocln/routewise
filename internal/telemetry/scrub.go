package telemetry

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/quocln/routewise/internal/config"
)

// Redacted replaces everything the scrubber removes.
const Redacted = "[redacted]"

// minTermLen keeps a one- or two-letter profile name from blanking every
// occurrence of those letters.
const minTermLen = 3

var (
	// A WireGuard key is 32 bytes of base64: 43 characters and one '='.
	wireGuardKeyRe = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
	// An Outline access key, and any other ss:// URL, runs to whitespace.
	shadowsocksURLRe = regexp.MustCompile(`(?i)\bss://\S+`)
	// The account name in a home directory path.
	homePathRe = regexp.MustCompile(`/Users/[^/\s"']+`)
	// An email address, whose domain would otherwise be left half-redacted.
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	// An IPv4 address with an optional prefix length.
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b(?:/\d{1,2})?`)
	// A run of hex digits, colons and dots holding at least one colon: an
	// IPv6 candidate, confirmed by netip below. A zone and a prefix length
	// are taken with it.
	ipv6CandidateRe = regexp.MustCompile(`(?i)[0-9a-f:.]*:[0-9a-f:.]*(?:%[a-z0-9_.-]+)?(?:/\d{1,3})?`)
	// Labels left in front of a redacted term, such as the "wiki." of
	// "wiki.<redacted suffix>", are part of the same host name.
	danglingLabelsRe = regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+\[redacted\]`)
	// A MAC address.
	macRe = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	// A DNS name: dot-separated labels, a wildcard allowed in the first, and
	// an alphabetic last label that replaceDomains checks against topLevel.
	domainRe = regexp.MustCompile(`(?i)(?:[a-z0-9-]*\*[a-z0-9-]*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}\b`)
)

// topLevel lists the top-level labels the scrubber treats as a DNS name. A
// dotted token such as fmt.Errorf or os.Exit is a Go identifier, not a host,
// and stays readable.
var topLevel = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(`
		com net org edu gov mil int info biz name pro mobi asia tel travel jobs
		io dev app ai co me tv cc xyz online site tech cloud store shop blog page
		link live work world today top club vip fun icu cyou rest zone network
		systems services solutions company group email digital agency global
		internal local lan home corp intranet private localdomain localhost
		test example invalid arpa onion vpn
		ac ad ae af ag al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi
		bj bm bn bo br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn cr cu cv cw
		cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd
		ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hn hr ht hu id ie il
		im in iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc
		li lk lr ls lt lu lv ly ma mc md mg mh mk ml mm mn mo mp mq mr ms mt mu
		mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk
		pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl
		sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt
		tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw`) {
		m[t] = true
	}
	// Source file extensions that are also country codes.
	for _, ext := range []string{"md", "sh", "py", "rs", "so", "pl", "ps", "mk", "pm", "ml", "cc", "ts", "cl", "sa"} {
		delete(m, ext)
	}
	return m
}()

// scrubTerms is the compiled set of configuration-derived values.
type scrubTerms struct {
	re *regexp.Regexp // nil when there are no terms
}

// Scrubber removes anything that identifies the user's traffic or network from
// a string. It is safe for concurrent use; SetTerms swaps the
// configuration-derived values atomically.
type Scrubber struct {
	terms atomic.Pointer[scrubTerms]
}

// NewScrubber returns a scrubber with no configuration-derived terms.
func NewScrubber() *Scrubber {
	s := &Scrubber{}
	s.terms.Store(&scrubTerms{})
	return s
}

// SetTerms replaces the exact values redacted before the generic rules run.
func (s *Scrubber) SetTerms(terms []string) {
	seen := map[string]bool{}
	var quoted []string
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if len(t) < minTermLen || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		quoted = append(quoted, regexp.QuoteMeta(t))
	}
	if len(quoted) == 0 {
		s.terms.Store(&scrubTerms{})
		return
	}
	// Longest first, so "vpn.example.com" wins over "example.com".
	slices.SortFunc(quoted, func(a, b string) int { return len(b) - len(a) })
	s.terms.Store(&scrubTerms{re: regexp.MustCompile(`(?i)` + strings.Join(quoted, "|"))})
}

// TermsFromConfig lists what the configuration says is private: every domain
// rule, every VPN profile name, and every VPN client with its executable name.
// A profile's server endpoint lives in its credentials, not here; the generic
// IP and host rules catch it wherever it appears.
func TermsFromConfig(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var terms []string
	addRules := func(rules []config.DomainRule) {
		for _, r := range rules {
			terms = append(terms, r.Pattern)
			// A wildcard "*.corp.example.com" also hides the suffix it covers.
			if suffix := config.WildcardSuffix(r.Pattern); suffix != "" {
				terms = append(terms, suffix)
			}
		}
	}
	addRules(cfg.Domains)
	for _, v := range cfg.VPNs {
		addRules(v.Domains)
		if config.IsBuiltinClient(v.Client) {
			continue
		}
		terms = append(terms, v.Client, strings.TrimSuffix(filepath.Base(v.Client), ".app"))
	}
	for _, p := range cfg.Profiles {
		terms = append(terms, p.Name)
	}
	return terms
}

// String returns s with private values replaced by Redacted.
func (s *Scrubber) String(in string) string {
	if in == "" {
		return in
	}
	out := in
	if t := s.terms.Load(); t != nil && t.re != nil {
		out = t.re.ReplaceAllString(out, Redacted)
		out = danglingLabelsRe.ReplaceAllString(out, Redacted)
	}
	out = wireGuardKeyRe.ReplaceAllString(out, Redacted)
	out = shadowsocksURLRe.ReplaceAllString(out, Redacted)
	out = homePathRe.ReplaceAllString(out, "/Users/"+Redacted)
	out = emailRe.ReplaceAllString(out, Redacted)
	out = macRe.ReplaceAllString(out, Redacted)
	out = replaceIPv6(out)
	out = replaceIPv4(out)
	out = replaceDomains(out)
	return out
}

func replaceIPv4(in string) string {
	return ipv4Re.ReplaceAllStringFunc(in, func(m string) string {
		addr, _, _ := strings.Cut(m, "/")
		if _, err := netip.ParseAddr(addr); err != nil {
			return m
		}
		return Redacted
	})
}

func replaceIPv6(in string) string {
	return ipv6CandidateRe.ReplaceAllStringFunc(in, func(m string) string {
		body, suffix := m, ""
		if i := strings.IndexAny(m, "%/"); i >= 0 {
			body, suffix = m[:i], m[i:]
		}
		start, end, ok := findIPv6(body)
		if !ok {
			return m
		}
		if end == len(body) {
			// The zone and prefix length belong to the address.
			return m[:start] + Redacted
		}
		return m[:start] + Redacted + body[end:] + suffix
	})
}

// maxIPv6Run bounds the trimming search on a long run of hex and colons.
const maxIPv6Run = 64

// findIPv6 locates an address inside a run of hex digits, colons and dots.
// Text such as "ip:2001:db8::1" leaves a stray leading colon, and a sentence
// may end with a dot or colon, so the run is trimmed until it parses.
func findIPv6(body string) (start, end int, ok bool) {
	if len(body) > maxIPv6Run {
		return 0, 0, false
	}
	starts := []int{0}
	if strings.HasPrefix(body, ":") && !strings.HasPrefix(body, "::") {
		starts = append(starts, 1)
	}
	for _, st := range starts {
		for e := len(body); e > st+1; e-- {
			if e < len(body) && body[e-1] != ':' && body[e-1] != '.' && !isHex(body[e-1]) {
				continue
			}
			if parsesAsIPv6(body[st:e]) {
				return st, e, true
			}
		}
	}
	return 0, 0, false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func parsesAsIPv6(s string) bool {
	if s == "" || s == "::" || !strings.Contains(s, ":") {
		return false
	}
	addr, err := netip.ParseAddr(s)
	return err == nil && (addr.Is6() || addr.Is4In6())
}

func replaceDomains(in string) string {
	return domainRe.ReplaceAllStringFunc(in, func(m string) string {
		i := strings.LastIndexByte(m, '.')
		if i < 0 || !topLevel[strings.ToLower(m[i+1:])] {
			return m
		}
		return Redacted
	})
}
