package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// maxProfileSecretBytes bounds a .conf file or key read by the CLI.
const maxProfileSecretBytes = 256 << 10

var (
	profileName string
	profileAuto bool
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage built-in WireGuard and Outline VPNs",
	Long: `Manage the VPNs the RouteWise helper runs itself: WireGuard tunnels from a
.conf file and Outline (Shadowsocks) tunnels from an access key. Each profile
gets its own domain list (see the app, or 'routewise add-domain') and routes
only that list through its own interface; nothing else changes.

Credentials are stored in the helper's private database and are never shown
again. Changing profiles needs the console user, like other changes.`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the built-in VPN profiles and their state",
	Args:  cobra.NoArgs,
	RunE:  runProfileList,
}

var profileImportWireGuardCmd = &cobra.Command{
	Use:   "import-wireguard <file>",
	Short: "Import a WireGuard .conf file as a profile",
	Long: `Import a WireGuard .conf file. Use "-" to read it from standard input.
The profile starts disconnected; --auto connects it whenever the helper starts.

Examples:
  routewise profile import-wireguard office.conf --name Office --auto`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileImportWireGuard,
}

var profileImportOutlineCmd = &cobra.Command{
	Use:   "import-outline",
	Short: "Import an Outline access key as a profile (read from stdin or a hidden prompt)",
	Long: `Import an Outline access key (ss:// or a dynamic ssconf:// key).

The key is a secret, so it is never taken as an argument: an argument shows in
the process list to every user on this Mac while the command runs, and stays in
your shell history. Pipe it in, or run the command with no input redirected and
type or paste it at the prompt, where it is not echoed.

The profile starts disconnected; --auto connects it as soon as it is imported
and again whenever the helper starts.

Examples:
  pbpaste | routewise profile import-outline --name Travel
  routewise profile import-outline --name Travel --auto`,
	Args: noKeyArgument,
	RunE: runProfileImportOutline,
}

// noKeyArgument refuses a key given on the command line. Its message never
// repeats the argument, which may be the key itself.
func noKeyArgument(cmd *cobra.Command, args []string) error {
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		return nil
	}
	return errors.New("import-outline does not take the key as an argument, because it would be visible " +
		"in the process list and shell history; pipe it in (pbpaste | routewise profile import-outline) " +
		"or run it with no argument to be prompted")
}

var profileConnectCmd = &cobra.Command{
	Use:   "connect <id|name>",
	Short: "Connect a profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProfileAction("profiles.connect", "Connecting", args[0])
	},
}

var profileDisconnectCmd = &cobra.Command{
	Use:   "disconnect <id|name>",
	Short: "Disconnect a profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProfileAction("profiles.disconnect", "Disconnected", args[0])
	},
}

var profileRemoveCmd = &cobra.Command{
	Use:   "remove <id|name>",
	Short: "Remove a profile, its credentials, and its domain list",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProfileAction("profiles.remove", "Removed", args[0])
	},
}

func init() {
	for _, c := range []*cobra.Command{profileImportWireGuardCmd, profileImportOutlineCmd} {
		c.Flags().StringVar(&profileName, "name", "", "profile name (default: derived from the key, or the kind)")
		c.Flags().BoolVar(&profileAuto, "auto", false, "connect this profile when the helper starts")
	}
	profileCmd.AddCommand(profileListCmd, profileImportWireGuardCmd, profileImportOutlineCmd,
		profileConnectCmd, profileDisconnectCmd, profileRemoveCmd)
	rootCmd.AddCommand(profileCmd)
}

func runProfileList(cmd *cobra.Command, args []string) error {
	var profiles []api.ProfileInfo
	if err := requireHelper(commandContext(cmd), "profiles.list", nil, &profiles); err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Println("No built-in VPN profiles. Import one with 'routewise profile import-wireguard' or 'import-outline'.")
		return nil
	}
	for _, p := range profiles {
		fmt.Println(formatProfile(p))
	}
	return nil
}

// formatProfile prints one profile on one line. It shows only what the helper
// reports, which never includes credentials.
func formatProfile(p api.ProfileInfo) string {
	line := fmt.Sprintf("%-8s  %-9s  %-16s  %s", p.ID, p.Kind, p.State, p.Name)
	var extra []string
	if p.Interface != "" {
		extra = append(extra, p.Interface)
	}
	if p.Server != "" {
		extra = append(extra, p.Server)
	}
	if p.AutoConnect {
		extra = append(extra, "auto")
	}
	if p.Stats != nil {
		extra = append(extra, fmt.Sprintf("rx %d tx %d", p.Stats.RxBytes, p.Stats.TxBytes))
		if p.Stats.LastHandshakeMs != nil {
			extra = append(extra, "handshake "+time.UnixMilli(*p.Stats.LastHandshakeMs).Format("15:04:05"))
		}
	}
	if len(extra) > 0 {
		line += "  (" + strings.Join(extra, ", ") + ")"
	}
	if p.Error != "" {
		line += "  error: " + p.Error
	}
	return line
}

// readStdinSecret returns the whole of standard input, bounded.
func readStdinSecret(stdin io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxProfileSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read standard input: %w", err)
	}
	if len(data) > maxProfileSecretBytes {
		return "", fmt.Errorf("input is larger than %d bytes", maxProfileSecretBytes)
	}
	return string(data), nil
}

// outlineKeyInput is where the Outline key comes from. stdinIsTerminal and
// prompt are fields so a test can drive both paths without a terminal.
type outlineKeyInput struct {
	stdin           io.Reader
	stdinIsTerminal func() bool
	prompt          func() (string, error)
}

// read returns the key: from the hidden prompt when standard input is a
// terminal, else from standard input. The key is never read from an argument.
func (in outlineKeyInput) read() (string, error) {
	var key string
	var err error
	if in.stdinIsTerminal != nil && in.stdinIsTerminal() {
		key, err = in.prompt()
	} else {
		key, err = readStdinSecret(in.stdin)
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(key) == "" {
		return "", errors.New("no access key given: pipe it in, or run the command in a terminal to be prompted")
	}
	return key, nil
}

// readConfigFile reads a .conf file, refusing anything but a regular file of
// sane size.
func readConfigFile(path string, stdin io.Reader) (string, error) {
	if path == "-" {
		return readStdinSecret(stdin)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxProfileSecretBytes {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxProfileSecretBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// wireGuardImportParams builds the profiles.import request for a .conf.
func wireGuardImportParams(text, name string, auto bool) api.ProfileImportParams {
	return api.ProfileImportParams{Kind: config.ProfileKindWireGuard, Name: name, WireguardConfig: text, AutoConnect: auto}
}

// outlineImportParams builds the profiles.import request for an access key.
func outlineImportParams(key, name string, auto bool) api.ProfileImportParams {
	return api.ProfileImportParams{Kind: config.ProfileKindOutline, Name: name, AccessKey: strings.TrimSpace(key), AutoConnect: auto}
}

func runProfileImportWireGuard(cmd *cobra.Command, args []string) error {
	text, err := readConfigFile(args[0], cmd.InOrStdin())
	if err != nil {
		return err
	}
	return submitProfileImport(wireGuardImportParams(text, profileName, profileAuto))
}

func runProfileImportOutline(cmd *cobra.Command, args []string) error {
	in := outlineKeyInput{stdin: cmd.InOrStdin()}
	// The hidden prompt applies only when the command really reads the process's
	// terminal; a stdin set by a caller (or a test) is read as given.
	if f, ok := in.stdin.(*os.File); ok && f == os.Stdin && len(args) == 0 {
		in.stdinIsTerminal = func() bool { return isTerminal(f) }
		in.prompt = func() (string, error) { return promptHidden(f, os.Stderr, "Outline access key (input is hidden): ") }
	}
	key, err := in.read()
	if err != nil {
		return err
	}
	return submitProfileImport(outlineImportParams(key, profileName, profileAuto))
}

// submitProfileImport sends an import to the helper. It is a variable so a test
// can see exactly what would be sent.
var submitProfileImport = importProfile

func importProfile(params api.ProfileImportParams) error {
	var result api.ProfileImportResult
	if err := requireHelper(context.Background(), "profiles.import", params, &result); err != nil {
		return err
	}
	fmt.Printf("Imported profile %s. Connect it with: routewise profile connect %s\n", result.ID, result.ID)
	return nil
}

func runProfileAction(method, verb, ref string) error {
	ctx := context.Background()
	var profiles []api.ProfileInfo
	if err := requireHelper(ctx, "profiles.list", nil, &profiles); err != nil {
		return err
	}
	p, err := resolveProfile(profiles, ref)
	if err != nil {
		return err
	}
	if err := requireHelper(ctx, method, api.ProfileIDParams{ID: p.ID}, nil); err != nil {
		return err
	}
	fmt.Printf("%s %s (%s)\n", verb, p.Name, p.ID)
	return nil
}

// resolveProfile finds the profile a user means: an exact ID, else a name
// (case-insensitive) that only one profile has.
func resolveProfile(profiles []api.ProfileInfo, ref string) (api.ProfileInfo, error) {
	for _, p := range profiles {
		if p.ID == ref {
			return p, nil
		}
	}
	var matches []api.ProfileInfo
	for _, p := range profiles {
		if strings.EqualFold(p.Name, ref) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return api.ProfileInfo{}, fmt.Errorf("no profile with id or name %q (see 'routewise profile list')", ref)
	}
	return api.ProfileInfo{}, fmt.Errorf("%d profiles are named %q; use the id", len(matches), ref)
}
