//go:build windows

package resolverfiles

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// nrptLocalPath holds the rules the DNS client reads from the local
	// machine, one subkey each.
	nrptLocalPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// nrptPolicyPath holds the rules Group Policy delivers. When it has any,
	// the DNS client ignores the local ones.
	nrptPolicyPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	dnsClientService = "Dnscache"
)

// registryNRPT is the NRPT backend over the Windows registry and the DNS
// Client service. It needs administrator rights, which the helper service has.
type registryNRPT struct{}

var _ nrptBackend = registryNRPT{}

func (registryNRPT) OwnedRules() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocalPath, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", nrptLocalPath, err)
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", nrptLocalPath, err)
	}
	var owned []string
	for _, name := range names {
		if strings.HasPrefix(name, nrptKeyPrefix) {
			owned = append(owned, name)
		}
	}
	return owned, nil
}

// WriteRule creates the rule's key if it is missing and sets the values that
// differ from what is stored. Every sync calls it for every domain, and the DNS
// client may watch the key, so an unchanged rule is left untouched.
func (registryNRPT) WriteRule(key string, values []regValue) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptLocalPath+`\`+key, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("create rule key %s: %w", key, err)
	}
	defer k.Close()
	for _, v := range values {
		if registryValueMatches(k, v) {
			continue
		}
		switch v.kind {
		case regDWord:
			err = k.SetDWordValue(v.name, v.dword)
		case regString:
			err = k.SetStringValue(v.name, v.str)
		case regMultiString:
			err = k.SetStringsValue(v.name, v.multi)
		}
		if err != nil {
			return fmt.Errorf("set %s on rule key %s: %w", v.name, key, err)
		}
	}
	return nil
}

// registryValueMatches reports whether k already holds v, with the same type
// and content. Any read error counts as a mismatch, so the value is written.
func registryValueMatches(k registry.Key, v regValue) bool {
	switch v.kind {
	case regDWord:
		got, _, err := k.GetIntegerValue(v.name)
		return err == nil && got == uint64(v.dword)
	case regString:
		got, _, err := k.GetStringValue(v.name)
		return err == nil && got == v.str
	case regMultiString:
		got, _, err := k.GetStringsValue(v.name)
		return err == nil && slices.Equal(got, v.multi)
	}
	return false
}

func (registryNRPT) DeleteRule(key string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptLocalPath+`\`+key)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete rule key %s: %w", key, err)
	}
	return nil
}

func (registryNRPT) PolicyManaged() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicyPath, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open %s: %w", nrptPolicyPath, err)
	}
	defer k.Close()
	info, err := k.Stat()
	if err != nil {
		return false, fmt.Errorf("read %s: %w", nrptPolicyPath, err)
	}
	return info.SubKeyCount > 0, nil
}

// Reload tells the DNS Client service its parameters changed, which makes it
// read the rule keys again (it caches them in memory, so registry writes alone
// do nothing), then flushes the resolver cache so names answered before the
// rules existed are asked again. A failed flush is only logged: the rules are
// live and cached answers age out.
func (registryNRPT) Reload() error {
	if err := dnsClientParamChange(); err != nil {
		return err
	}
	if err := flushResolverCache(); err != nil {
		slog.Warn("could not flush the DNS resolver cache", "error", err)
	}
	return nil
}

// dnsClientParamChange sends SERVICE_CONTROL_PARAMCHANGE to Dnscache. The
// service is opened with only the pause/continue right, the one that permits
// this control code, because the service manager does not grant full access to
// it.
func dnsClientParamChange() error {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(m)
	name, err := windows.UTF16PtrFromString(dnsClientService)
	if err != nil {
		return err
	}
	s, err := windows.OpenService(m, name, windows.SERVICE_PAUSE_CONTINUE)
	if err != nil {
		return fmt.Errorf("open the %s service: %w", dnsClientService, err)
	}
	defer windows.CloseServiceHandle(s)
	var status windows.SERVICE_STATUS
	if err := windows.ControlService(s, windows.SERVICE_CONTROL_PARAMCHANGE, &status); err != nil {
		if errors.Is(err, windows.ERROR_INVALID_SERVICE_CONTROL) {
			// A DNS client that does not take the control still watches its
			// policy keys; the flush after this makes the rules count at once.
			slog.Warn("the DNS Client service refused the parameter-change notice; relying on its registry watch", "error", err)
			return nil
		}
		return fmt.Errorf("notify the %s service of a parameter change: %w", dnsClientService, err)
	}
	return nil
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flushResolverCache empties the DNS client's cache, as `ipconfig /flushdns`.
func flushResolverCache() error {
	r, _, err := procDnsFlushResolverCache.Call()
	if r == 0 {
		return fmt.Errorf("DnsFlushResolverCache: %w", err)
	}
	return nil
}
