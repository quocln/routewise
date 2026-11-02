package daemon

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
)

// The methods below back the profiles.* RPCs. A secret enters through
// ProfileImport and ProfileUpdate, is validated by parsing, and goes straight
// to the secret store. It is never put in a result, an error, a log line, or
// an activity event.

// ProfilesList reports every profile with its live state.
func (d *Daemon) ProfilesList() []api.ProfileInfo {
	profiles := d.store.Profiles()
	out := make([]api.ProfileInfo, 0, len(profiles))
	for _, p := range profiles {
		info := api.ProfileInfo{
			ID: p.ID, Kind: p.Kind, Name: p.Name, AutoConnect: p.AutoConnect,
			DNS: slices.Clone(p.DNS), State: api.ProfileDisconnected,
		}
		if info.DNS == nil {
			info.DNS = []string{}
		}
		snap := d.tunnels.snapshot(p.ID)
		if snap.exists {
			info.State, info.Error = snap.state, snap.err
			info.Interface, info.Server = snap.iface, snap.server
		}
		if snap.tunnel != nil {
			// Asked outside the manager's lock: a device read can take a moment. A
			// connecting or unhealthy tunnel reports too: its last handshake is
			// what explains why it is not connected.
			info.Stats = snap.tunnel.Stats()
		}
		if (!snap.exists || snap.state == api.ProfileDisconnected) && !d.hasSecret(p.ID) {
			info.State = api.ProfileNeedsCredentials
		}
		out = append(out, info)
	}
	return out
}

// ProfileImport adds a built-in VPN. The secret is parsed to validate it and
// stored; the profile starts disconnected.
func (d *Daemon) ProfileImport(p api.ProfileImportParams) (string, error) {
	d.tunnels.profileMu.Lock()
	defer d.tunnels.profileMu.Unlock()
	if d.secrets == nil {
		return "", errors.New("profile credential storage is not available")
	}
	secret, err := secretForKind(p.Kind, p.WireguardConfig, p.AccessKey)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("%w: a %s profile needs its credentials", api.ErrRejected, p.Kind)
	}
	dns, label, err := validateSecret(p.Kind, secret)
	if err != nil {
		return "", fmt.Errorf("%w: %w", api.ErrRejected, err)
	}
	if err := d.checkProfileUnique("", p.Kind, secret); err != nil {
		return "", err
	}
	if dns == nil {
		dns = []string{}
	}

	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = d.uniqueProfileName(defaultProfileName(p.Kind, label))
	}
	if err := config.ValidateProfileName(name); err != nil {
		return "", fmt.Errorf("%w: %w", api.ErrRejected, err)
	}

	id, err := d.newProfileID()
	if err != nil {
		return "", err
	}
	profile := config.TunnelProfile{ID: id, Kind: p.Kind, Name: name, AutoConnect: p.AutoConnect, DNS: dns}

	// The secret goes in first so the profile is never visible without the
	// means to connect; if the profile is then refused the secret is dropped.
	if err := d.secrets.SetProfileSecret(id, secret); err != nil {
		return "", errors.New("could not store the profile credentials")
	}
	if _, err := d.store.AddProfile(profile); err != nil {
		if delErr := d.secrets.DeleteProfileSecret(id); delErr != nil {
			d.logger.Warn("could not remove the credentials of a refused profile", "profile", id, "error", delErr)
		}
		return "", classifyConfigError(err)
	}
	d.logger.Info("built-in VPN profile imported", "profile", name, "kind", p.Kind, "id", id)
	d.TriggerSync()
	// An auto-connect profile connects now, not only at the next helper start.
	// The import itself succeeded, so a failure to connect is reported through
	// the profile's state and the log, not as a failed import.
	if p.AutoConnect {
		if err := d.connectProfile(id); err != nil {
			d.logger.Warn("could not auto-connect the imported profile", "profile", name, "error", err)
		}
	}
	return id, nil
}

// uniqueProfileName appends a number until no profile has the name.
func (d *Daemon) uniqueProfileName(base string) string {
	taken := make(map[string]bool)
	for _, p := range d.store.Profiles() {
		taken[strings.ToLower(p.Name)] = true
	}
	name := base
	for i := 2; taken[strings.ToLower(name)]; i++ {
		name = fmt.Sprintf("%s %d", base, i)
	}
	return name
}

func (d *Daemon) newProfileID() (string, error) {
	for range 8 {
		id, err := config.NewProfileID()
		if err != nil {
			return "", err
		}
		if _, exists := d.store.Profile(id); !exists {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a profile id")
}

// ProfileUpdate changes a profile's name, auto-connect, DNS, or secret. A
// connected profile whose tunnel depends on what changed (its name, its DNS,
// or its secret) reconnects.
func (d *Daemon) ProfileUpdate(p api.ProfileUpdateParams) error {
	d.tunnels.profileMu.Lock()
	defer d.tunnels.profileMu.Unlock()
	current, ok := d.store.Profile(p.ID)
	if !ok {
		return fmt.Errorf("%w: profile %q does not exist", api.ErrRejected, p.ID)
	}
	secret, err := secretForKind(current.Kind, p.WireguardConfig, p.AccessKey)
	if err != nil {
		return err
	}
	if secret != "" {
		if d.secrets == nil {
			return errors.New("profile credential storage is not available")
		}
		if _, _, err := validateSecret(current.Kind, secret); err != nil {
			return fmt.Errorf("%w: %w", api.ErrRejected, err)
		}
		if err := d.checkProfileUnique(p.ID, current.Kind, secret); err != nil {
			return err
		}
	}
	var dns []string
	if p.DNS != nil {
		if dns, err = config.NormalizeProfileDNS(*p.DNS); err != nil {
			return fmt.Errorf("%w: %w", api.ErrRejected, err)
		}
	}
	if p.Name != nil {
		if err := config.ValidateProfileName(strings.TrimSpace(*p.Name)); err != nil {
			return fmt.Errorf("%w: %w", api.ErrRejected, err)
		}
	}

	// The new secret is stored before the metadata commits and put back if the
	// commit is refused, so a failed update changes neither.
	var previous string
	hadPrevious := false
	if secret != "" {
		if old, err := d.secrets.ProfileSecret(p.ID); err == nil {
			previous, hadPrevious = old, true
		}
		if err := d.secrets.SetProfileSecret(p.ID, secret); err != nil {
			return errors.New("could not store the profile credentials")
		}
	}
	_, err = d.store.UpdateProfile(p.ID, func(t *config.TunnelProfile) error {
		if p.Name != nil {
			t.Name = strings.TrimSpace(*p.Name)
		}
		if p.AutoConnect != nil {
			t.AutoConnect = *p.AutoConnect
		}
		if p.DNS != nil {
			t.DNS = dns
		}
		return nil
	})
	if err != nil {
		if secret != "" {
			d.restoreSecret(p.ID, previous, hadPrevious)
		}
		return classifyConfigError(err)
	}

	updated, _ := d.store.Profile(p.ID)
	needsRestart := secret != "" || updated.Name != current.Name || !slices.Equal(updated.DNS, current.DNS)
	d.logger.Info("built-in VPN profile updated", "profile", updated.Name, "id", p.ID, "credentials_replaced", secret != "")
	d.TriggerSync()
	if needsRestart && d.tunnels.snapshot(p.ID).exists {
		return d.restartIfWanted(p.ID)
	}
	return nil
}

// restoreSecret puts a replaced secret back after a refused update.
func (d *Daemon) restoreSecret(id, previous string, had bool) {
	var err error
	if had {
		err = d.secrets.SetProfileSecret(id, previous)
	} else {
		err = d.secrets.DeleteProfileSecret(id)
	}
	if err != nil {
		d.logger.Error("could not restore the profile credentials after a refused update", "profile", id)
	}
}

// restartIfWanted reconnects a profile that has a run (connected, connecting,
// or waiting to retry) so it picks up what changed.
func (d *Daemon) restartIfWanted(id string) error {
	if !d.tunnels.snapshot(id).exists {
		return nil
	}
	if err := d.connectProfile(id); err != nil {
		// The change itself is saved; only the reconnect failed.
		d.logger.Warn("could not reconnect the profile after an update", "profile", id, "error", err)
	}
	return nil
}

// ProfileRemove disconnects a profile and deletes it, its secret, and its
// domain list.
func (d *Daemon) ProfileRemove(id string) error {
	p, ok := d.store.Profile(id)
	if !ok {
		return fmt.Errorf("%w: profile %q does not exist", api.ErrRejected, id)
	}
	// Stopping the run and removing the profile are one step under ctlMu, so a
	// connect that arrives between them cannot start a run for a profile about to
	// vanish.
	d.tunnels.ctlMu.Lock()
	d.stopRunLocked(id)
	_, err := d.store.RemoveProfile(id)
	d.tunnels.ctlMu.Unlock()
	if err != nil {
		return classifyConfigError(err)
	}
	if d.secrets != nil {
		if err := d.secrets.DeleteProfileSecret(id); err != nil {
			d.logger.Warn("could not delete the credentials of a removed profile", "profile", p.Name, "id", id, "error", err)
		}
	}
	d.logger.Info("built-in VPN profile removed", "profile", p.Name, "id", id)
	d.TriggerSync()
	return nil
}

// ProfileConnect connects a profile.
func (d *Daemon) ProfileConnect(id string) error { return d.connectProfile(id) }

// ProfileDisconnect disconnects a profile and stops reconnecting it.
func (d *Daemon) ProfileDisconnect(id string) error {
	if _, ok := d.store.Profile(id); !ok {
		return fmt.Errorf("%w: profile %q does not exist", api.ErrRejected, id)
	}
	d.stopRun(id)
	return nil
}

// reconcileProfiles applies a config import to the running tunnels: a profile
// the import dropped (or changed to another kind) is disconnected and loses
// its secret, and one whose name or DNS changed reconnects. A profile the
// import adds has no secret until the user adds one.
func (d *Daemon) reconcileProfiles(before, after []config.TunnelProfile) {
	for _, old := range before {
		now, kept := profileByID(after, old.ID)
		switch {
		case !kept || now.Kind != old.Kind:
			d.stopRun(old.ID)
			if d.secrets != nil {
				if err := d.secrets.DeleteProfileSecret(old.ID); err != nil && !errors.Is(err, configdb.ErrNoSecret) {
					d.logger.Warn("could not delete the credentials of a dropped profile", "id", old.ID, "error", err)
				}
			}
		case now.Name != old.Name || !slices.Equal(now.DNS, old.DNS):
			_ = d.restartIfWanted(old.ID)
		}
	}
}

func profileByID(profiles []config.TunnelProfile, id string) (config.TunnelProfile, bool) {
	for _, p := range profiles {
		if p.ID == id {
			return p, true
		}
	}
	return config.TunnelProfile{}, false
}
