package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/quocln/routewise/internal/api"
)

func TestProfileCommandsAreRegisteredWithTheDocumentedShapes(t *testing.T) {
	cases := []struct {
		args    []string
		wantUse string
		ok      bool
	}{
		{[]string{"profile", "list"}, "list", true},
		{[]string{"profile", "list", "extra"}, "", false},
		{[]string{"profile", "import-wireguard", "office.conf", "--name", "Office", "--auto"}, "import-wireguard <file>", true},
		{[]string{"profile", "import-wireguard"}, "", false},
		// The key is never an argument: it is read from stdin or a hidden prompt.
		{[]string{"profile", "import-outline", "--name", "N"}, "import-outline", true},
		{[]string{"profile", "import-outline", "-"}, "import-outline", true},
		{[]string{"profile", "import-outline"}, "import-outline", true},
		{[]string{"profile", "import-outline", "ss://abc@host:1", "--name", "N"}, "", false},
		{[]string{"profile", "connect", "office"}, "connect <id|name>", true},
		{[]string{"profile", "disconnect", "office"}, "disconnect <id|name>", true},
		{[]string{"profile", "remove", "0a1b2c3d"}, "remove <id|name>", true},
		{[]string{"profile", "remove"}, "", false},
		{[]string{"profile", "remove", "a", "b"}, "", false},
	}
	for _, c := range cases {
		cmd, rest, err := rootCmd.Find(c.args)
		if err != nil || cmd == nil || cmd == rootCmd || cmd == profileCmd {
			t.Errorf("%v: no subcommand found (err %v)", c.args, err)
			continue
		}
		if c.ok && cmd.Use != c.wantUse {
			t.Errorf("%v resolved to %q, want %q", c.args, cmd.Use, c.wantUse)
		}
		// Parse flags the way cobra does before running, then validate the args.
		if err := cmd.ParseFlags(rest); err != nil {
			t.Errorf("%v: flags: %v", c.args, err)
			continue
		}
		argErr := cmd.ValidateArgs(cmd.Flags().Args())
		if c.ok && argErr != nil {
			t.Errorf("%v: unexpected argument error %v", c.args, argErr)
		}
		if !c.ok && argErr == nil {
			t.Errorf("%v: expected an argument error", c.args)
		}
	}
}

func TestImportFlagsReachTheRequest(t *testing.T) {
	for _, c := range []*cobra.Command{profileImportWireGuardCmd, profileImportOutlineCmd} {
		if c.Flags().Lookup("name") == nil || c.Flags().Lookup("auto") == nil {
			t.Errorf("%s needs --name and --auto", c.Use)
		}
	}
	wg := wireGuardImportParams("[Interface]\n", "Office", true)
	if wg.Kind != "wireguard" || wg.Name != "Office" || !wg.AutoConnect || wg.WireguardConfig == "" || wg.AccessKey != "" {
		t.Errorf("wireguard params = %+v", wg)
	}
	ol := outlineImportParams("  ss://abc@host:1\n", "Travel", false)
	if ol.Kind != "outline" || ol.AccessKey != "ss://abc@host:1" || ol.WireguardConfig != "" || ol.AutoConnect {
		t.Errorf("outline params = %+v", ol)
	}
}

func TestSecretsCanComeFromStandardInput(t *testing.T) {
	got, err := readStdinSecret(strings.NewReader("ss://key@host:1\n"))
	if err != nil || got != "ss://key@host:1\n" {
		t.Errorf("stdin = %q, %v", got, err)
	}
	if _, err := readStdinSecret(strings.NewReader(strings.Repeat("x", maxProfileSecretBytes+1))); err == nil {
		t.Error("oversized input must be refused")
	}
	if _, err := readConfigFile(t.TempDir(), nil); err == nil {
		t.Error("a directory is not a config file")
	}
	if _, err := readConfigFile("/nonexistent/office.conf", nil); err == nil {
		t.Error("a missing file must be an error")
	}
}

func TestResolveProfileByIDOrName(t *testing.T) {
	profiles := []api.ProfileInfo{
		{ID: "0a1b2c3d", Name: "Office"},
		{ID: "4e5f6a7b", Name: "Travel"},
		{ID: "11223344", Name: "dup"},
		{ID: "55667788", Name: "DUP"},
	}
	for ref, want := range map[string]string{"0a1b2c3d": "0a1b2c3d", "office": "0a1b2c3d", "TRAVEL": "4e5f6a7b"} {
		p, err := resolveProfile(profiles, ref)
		if err != nil || p.ID != want {
			t.Errorf("resolve %q = %+v, %v; want %s", ref, p, err, want)
		}
	}
	if _, err := resolveProfile(profiles, "dup"); err == nil || !strings.Contains(err.Error(), "use the id") {
		t.Errorf("an ambiguous name must ask for the id, got %v", err)
	}
	if _, err := resolveProfile(profiles, "nope"); err == nil {
		t.Error("an unknown profile must be an error")
	}
	if p, err := resolveProfile(profiles, "55667788"); err != nil || p.Name != "DUP" {
		t.Errorf("an id resolves even when names collide: %+v %v", p, err)
	}
}

func TestFormatProfileShowsStateAndNeverMoreThanTheHelperSends(t *testing.T) {
	ms := int64(1793000000000)
	line := formatProfile(api.ProfileInfo{
		ID: "0a1b2c3d", Kind: "wireguard", Name: "Office", State: "connected", Interface: "utun5",
		Server: "vpn.example.com:51820", AutoConnect: true,
		Stats: &api.ProfileStats{RxBytes: 10, TxBytes: 20, LastHandshakeMs: &ms},
	})
	for _, want := range []string{"0a1b2c3d", "wireguard", "connected", "Office", "utun5", "vpn.example.com:51820", "auto", "rx 10 tx 20", "handshake"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %q", line, want)
		}
	}
	errLine := formatProfile(api.ProfileInfo{ID: "4e5f6a7b", Kind: "outline", Name: "Travel", State: "error", Error: "no route to host"})
	if !strings.Contains(errLine, "error: no route to host") {
		t.Errorf("line %q lacks the error", errLine)
	}
}

// --- the Outline key never travels as an argument ---

const cliTestKey = "ss://Y2hhY2hhMjA6Q0xJU0VDUkVUS0VZMTIz@203.0.113.9:8388#Travel"

// capturedImport replaces the helper call with a recorder for one test.
func capturedImport(t *testing.T) *[]api.ProfileImportParams {
	t.Helper()
	var got []api.ProfileImportParams
	prev := submitProfileImport
	submitProfileImport = func(p api.ProfileImportParams) error { got = append(got, p); return nil }
	t.Cleanup(func() { submitProfileImport = prev })
	return &got
}

func runOutlineImport(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut strings.Builder
	cmd := profileImportOutlineCmd
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	t.Cleanup(func() { cmd.SetIn(nil); cmd.SetOut(nil); cmd.SetErr(nil) })
	if err = cmd.ValidateArgs(args); err != nil {
		return out.String(), errOut.String(), err
	}
	err = cmd.RunE(cmd, args)
	return out.String(), errOut.String(), err
}

func TestImportOutlineReadsTheKeyFromStandardInput(t *testing.T) {
	got := capturedImport(t)
	profileName, profileAuto = "Travel", true
	t.Cleanup(func() { profileName, profileAuto = "", false })
	stdout, stderr, err := runOutlineImport(t, cliTestKey+"\n")
	if err != nil {
		t.Fatalf("import from stdin: %v", err)
	}
	if len(*got) != 1 || (*got)[0].AccessKey != cliTestKey || (*got)[0].Kind != "outline" || !(*got)[0].AutoConnect || (*got)[0].Name != "Travel" {
		t.Fatalf("request = %+v", *got)
	}
	for _, out := range []string{stdout, stderr} {
		if strings.Contains(out, "CLISECRETKEY") || strings.Contains(out, "Y2hhY2hhMjA6") {
			t.Errorf("the key was echoed to the terminal: %q", out)
		}
	}

	// "-" is the explicit form of the same thing.
	*got = nil
	if _, _, err := runOutlineImport(t, cliTestKey, "-"); err != nil || len(*got) != 1 {
		t.Errorf("import with -: %v, requests %d", err, len(*got))
	}
}

func TestImportOutlineRefusesAKeyGivenAsAnArgumentWithoutEchoingIt(t *testing.T) {
	got := capturedImport(t)
	_, _, err := runOutlineImport(t, "", cliTestKey)
	if err == nil {
		t.Fatal("a key given as an argument must be refused")
	}
	if strings.Contains(err.Error(), "CLISECRETKEY") || strings.Contains(err.Error(), "Y2hhY2hhMjA6") || strings.Contains(err.Error(), "203.0.113.9") {
		t.Errorf("the refusal echoed the key: %v", err)
	}
	if !strings.Contains(err.Error(), "pipe") {
		t.Errorf("the refusal must say what to do instead: %v", err)
	}
	if len(*got) != 0 {
		t.Error("nothing may be sent to the helper for a refused key")
	}
	long := profileImportOutlineCmd.Long + profileImportOutlineCmd.Example + profileImportOutlineCmd.Use
	if strings.Contains(long, "'ss://") {
		t.Error("the help text must not show a key on the command line")
	}
	if !strings.Contains(long, "import-outline") || !strings.Contains(long, "pbpaste") {
		t.Error("the help text must show the stdin form")
	}
}

func TestOutlineKeyInputPromptsOnlyOnATerminalAndRejectsEmptyInput(t *testing.T) {
	prompted := 0
	prompt := func() (string, error) { prompted++; return " " + cliTestKey + "\n", nil }

	// A terminal: the hidden prompt is used and stdin is not read.
	tty := outlineKeyInput{stdin: strings.NewReader("ignored"), stdinIsTerminal: func() bool { return true }, prompt: prompt}
	key, err := tty.read()
	if err != nil || prompted != 1 || strings.TrimSpace(key) != cliTestKey {
		t.Errorf("terminal: key %q, prompted %d, err %v", key, prompted, err)
	}

	// A pipe: stdin is read and nothing is prompted.
	pipe := outlineKeyInput{stdin: strings.NewReader(cliTestKey), stdinIsTerminal: func() bool { return false }, prompt: prompt}
	if key, err := pipe.read(); err != nil || key != cliTestKey || prompted != 1 {
		t.Errorf("pipe: key %q, prompted %d, err %v", key, prompted, err)
	}

	// Nothing given.
	for _, in := range []outlineKeyInput{
		{stdin: strings.NewReader("  \n")},
		{stdin: strings.NewReader(""), stdinIsTerminal: func() bool { return true }, prompt: func() (string, error) { return "\n", nil }},
	} {
		if _, err := in.read(); err == nil {
			t.Error("an empty key must be refused")
		}
	}
	// A failing prompt is an error, not an empty key.
	failing := outlineKeyInput{stdinIsTerminal: func() bool { return true }, prompt: func() (string, error) { return "", errors.New("no tty") }}
	if _, err := failing.read(); err == nil {
		t.Error("a prompt failure must be reported")
	}
}
