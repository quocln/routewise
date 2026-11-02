package outlinetunnel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestParseAccessKey(t *testing.T) {
	const pw = "s3cr3t/pass+word"
	tests := []struct {
		name string
		in   string
		want Key
	}{
		{
			name: "sip002 base64url with tag",
			in:   "ss://" + b64url("chacha20-ietf-poly1305:"+pw) + "@203.0.113.5:8388/#My%20Server",
			want: Key{Method: CipherChaCha20, Password: pw, Host: "203.0.113.5", Port: 8388, Tag: "My Server"},
		},
		{
			name: "sip002 padded std base64, no slash",
			in:   "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:"+pw)) + "@example.com:443#t",
			want: Key{Method: CipherAES256, Password: pw, Host: "example.com", Port: 443, Tag: "t"},
		},
		{
			name: "sip002 percent-encoded plain userinfo",
			in:   "ss://aes-128-gcm:p%40ss%2Fw0rd@example.com:1234",
			want: Key{Method: CipherAES128, Password: "p@ss/w0rd", Host: "example.com", Port: 1234},
		},
		{
			name: "sip002 prefix",
			in:   "ss://" + b64url("aes-192-gcm:pw") + "@h.example:1/?prefix=POST%20",
			want: Key{Method: CipherAES192, Password: "pw", Host: "h.example", Port: 1, Prefix: []byte("POST ")},
		},
		{
			name: "prefix latin1 bytes",
			in:   "ss://" + b64url("aes-192-gcm:pw") + "@h.example:1/?prefix=%16%03%01%C2%80",
			want: Key{Method: CipherAES192, Password: "pw", Host: "h.example", Port: 1, Prefix: []byte{0x16, 0x03, 0x01, 0x80}},
		},
		{
			name: "sip002 ipv6 host",
			in:   "ss://" + b64url("aes-128-gcm:pw") + "@[2001:db8::1]:8388",
			want: Key{Method: CipherAES128, Password: "pw", Host: "2001:db8::1", Port: 8388},
		},
		{
			name: "legacy base64 with tag",
			in:   "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pa@ss@198.51.100.1:9000")) + "#legacy",
			want: Key{Method: CipherChaCha20, Password: "pa@ss", Host: "198.51.100.1", Port: 9000, Tag: "legacy"},
		},
		{
			name: "legacy unpadded",
			in:   "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:pw@host.test:65535")),
			want: Key{Method: CipherAES256, Password: "pw", Host: "host.test", Port: 65535},
		},
		{
			name: "method case-insensitive, scheme case-insensitive, whitespace",
			in:   "  SS://" + b64url("AES-256-GCM:pw") + "@h.test:2 \n",
			want: Key{Method: CipherAES256, Password: "pw", Host: "h.test", Port: 2},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAccessKey(tc.in)
			if err != nil {
				t.Fatalf("ParseAccessKey: %v", err)
			}
			if got.Method != tc.want.Method || got.Password != tc.want.Password || got.Host != tc.want.Host ||
				got.Port != tc.want.Port || got.Tag != tc.want.Tag || !bytes.Equal(got.Prefix, tc.want.Prefix) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseAccessKeyRejects(t *testing.T) {
	const pw = "TOPSECRETPASSWORD"
	ok := b64url("aes-256-gcm:" + pw)
	tests := []struct {
		name, in, wantSub string
	}{
		{"not ss", "vless://x@h:1", "start with ss://"},
		{"plugin", "ss://" + ok + "@h.test:1/?plugin=v2ray-plugin%3Bserver", "plugin"},
		{"bad cipher", "ss://" + b64url("rc4-md5:"+pw) + "@h.test:1", "unsupported cipher"},
		{"stream cipher", "ss://" + b64url("aes-256-cfb:"+pw) + "@h.test:1", "unsupported cipher"},
		{"port zero", "ss://" + ok + "@h.test:0", "port"},
		{"port too big", "ss://" + ok + "@h.test:70000", "port"},
		{"port not number", "ss://" + ok + "@h.test:abc", "port"},
		{"no port", "ss://" + ok + "@h.test", "host:port"},
		{"bad host", "ss://" + ok + "@bad_host!.test:1", "host"},
		{"empty host", "ss://" + ok + "@:1", "host"},
		{"bad base64 userinfo", "ss://!!!!@h.test:1", "base64"},
		{"userinfo without colon", "ss://" + b64url("justmethod") + "@h.test:1", "method:password"},
		{"empty password", "ss://" + b64url("aes-256-gcm:") + "@h.test:1", "empty password"},
		{"legacy garbage", "ss://" + b64url("nothing here"), "legacy"},
		{"unexpected path", "ss://" + ok + "@h.test:1/extra", "path"},
		{"bad percent in userinfo", "ss://aes-256-gcm:" + pw + "%zz@h.test:1", "percent-encoding"},
		{"empty", "ss://", "path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAccessKey(tc.in)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
			if strings.Contains(err.Error(), pw) {
				t.Fatalf("error leaks the password: %q", err)
			}
		})
	}
}

func TestKeyRedaction(t *testing.T) {
	k := Key{Method: CipherAES256, Password: "hunter2", Host: "h.test", Port: 1}
	if got := k.Redacted(); got.Password != "" || got.Host != "h.test" {
		t.Fatalf("Redacted = %+v", got)
	}
	if k.Password != "hunter2" {
		t.Fatal("Redacted mutated the receiver")
	}
	for _, s := range []string{k.String(), strings.TrimSpace(fmtV(k)), fmtV(&k)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("formatting leaks the password: %q", s)
		}
	}
}

func fmtV(v any) string { return fmt.Sprintf("%v|%+v", v, v) }
