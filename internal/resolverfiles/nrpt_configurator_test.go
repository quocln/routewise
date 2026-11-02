package resolverfiles

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fakeNRPT is an in-memory registry: key -> values.
type fakeNRPT struct {
	rules   map[string][]regValue
	managed bool
	reloads int
	writes  int

	failWrite  error
	failReload error
}

func newFakeNRPT() *fakeNRPT {
	return &fakeNRPT{rules: map[string][]regValue{}}
}

func (f *fakeNRPT) OwnedRules() ([]string, error) {
	var out []string
	for k := range f.rules {
		if strings.HasPrefix(k, nrptKeyPrefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (f *fakeNRPT) WriteRule(key string, values []regValue) error {
	if f.failWrite != nil {
		return f.failWrite
	}
	f.writes++
	f.rules[key] = values
	return nil
}

func (f *fakeNRPT) DeleteRule(key string) error { delete(f.rules, key); return nil }

func (f *fakeNRPT) PolicyManaged() (bool, error) { return f.managed, nil }

func (f *fakeNRPT) Reload() error {
	if f.failReload != nil {
		return f.failReload
	}
	f.reloads++
	return nil
}

func testNRPT(f *fakeNRPT) *NRPT { return newNRPT(f, "127.0.0.1", 53) }

func value(t *testing.T, vals []regValue, name string) regValue {
	t.Helper()
	for _, v := range vals {
		if v.name == name {
			return v
		}
	}
	t.Fatalf("value %q missing from %v", name, vals)
	return regValue{}
}

func TestNRPTRuleValues(t *testing.T) {
	f := newFakeNRPT()
	if _, err := testNRPT(f).Apply([]string{"Corp.Example.com"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	vals, ok := f.rules[nrptRuleKey("corp.example.com")]
	if !ok || len(f.rules) != 1 {
		t.Fatalf("rules = %v, want one rule at %s", f.rules, nrptRuleKey("corp.example.com"))
	}
	if v := value(t, vals, "Name"); v.kind != regMultiString || !reflect.DeepEqual(v.multi, []string{".corp.example.com", "corp.example.com"}) {
		t.Errorf("Name = %+v", v)
	}
	if v := value(t, vals, "GenericDNSServers"); v.kind != regString || v.str != "127.0.0.1" {
		t.Errorf("GenericDNSServers = %+v", v)
	}
	if v := value(t, vals, "ConfigOptions"); v.kind != regDWord || v.dword != 0x8 {
		t.Errorf("ConfigOptions = %+v", v)
	}
	if v := value(t, vals, "Version"); v.kind != regDWord || v.dword != 2 {
		t.Errorf("Version = %+v", v)
	}
	if v := value(t, vals, "IPSECCARestriction"); v.kind != regString || v.str != "" {
		t.Errorf("IPSECCARestriction = %+v", v)
	}
}

func TestNRPTRuleKeyIsStableAndRegistrySafe(t *testing.T) {
	a, b := nrptRuleKey("corp.example.com"), nrptRuleKey("corp.example.com")
	if a != b {
		t.Errorf("key changed between calls: %q vs %q", a, b)
	}
	if a == nrptRuleKey("corp.example.org") {
		t.Error("two domains share a key")
	}
	long := nrptRuleKey(strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.com")
	if !strings.HasPrefix(a, "RouteWise-") || len(long) != len(a) || strings.ContainsAny(long, `\/ `) {
		t.Errorf("keys %q, %q are not fixed-length registry names", a, long)
	}
}

func TestNRPTApplyReplacesTheWholeSetAndReloadsOnChange(t *testing.T) {
	f := newFakeNRPT()
	f.rules["{someone-elses}"] = nil
	n := testNRPT(f)

	if _, err := n.Apply([]string{"b.example.com", "a.example.com"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := n.Active(); !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("Active = %v", got)
	}
	if f.reloads != 1 {
		t.Errorf("reloads = %d, want 1", f.reloads)
	}

	// The same set again rewrites the rules but does not reload.
	writes := f.writes
	if _, err := n.Apply([]string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatalf("Apply again: %v", err)
	}
	if f.reloads != 1 || f.writes != writes+2 {
		t.Errorf("reloads = %d, writes = %d; want 1 reload and every rule rewritten", f.reloads, f.writes-writes)
	}

	if _, err := n.Apply([]string{"c.example.com"}); err != nil {
		t.Fatalf("Apply shrink: %v", err)
	}
	if _, ok := f.rules[nrptRuleKey("a.example.com")]; ok {
		t.Error("rule for a removed domain is still present")
	}
	if _, ok := f.rules["{someone-elses}"]; !ok {
		t.Error("a rule RouteWise does not own was removed")
	}
	if f.reloads != 2 {
		t.Errorf("reloads = %d, want 2", f.reloads)
	}
}

func TestNRPTApplyRestoresARuleSomeoneDeleted(t *testing.T) {
	f := newFakeNRPT()
	n := testNRPT(f)
	if _, err := n.Apply([]string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	delete(f.rules, nrptRuleKey("a.example.com")) // the DNS client dropped it
	if _, err := n.Apply([]string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.rules[nrptRuleKey("a.example.com")]; !ok {
		t.Error("rule not restored")
	}
	if f.reloads != 2 {
		t.Errorf("reloads = %d, want a reload after the restore", f.reloads)
	}
}

func TestNRPTEmptyApplyAndRemoveAllDeleteOnlyOwnedRules(t *testing.T) {
	f := newFakeNRPT()
	f.rules["{someone-elses}"] = nil
	n := testNRPT(f)
	if _, err := n.Apply([]string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Apply(nil); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if len(f.rules) != 1 || n.Active() != nil {
		t.Errorf("rules = %v, active = %v after an empty Apply", f.rules, n.Active())
	}

	// A previous process left rules behind.
	f.rules[nrptRuleKey("old.example.com")] = nil
	reloads := f.reloads
	if err := testNRPT(f).RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if len(f.rules) != 1 || f.reloads != reloads+1 {
		t.Errorf("rules = %v, reloads = %d; want only the foreign rule and one reload", f.rules, f.reloads-reloads)
	}
	if err := testNRPT(f).RemoveAll(); err != nil || f.reloads != reloads+1 {
		t.Errorf("RemoveAll with nothing to remove = %v, reloaded again = %v", err, f.reloads != reloads+1)
	}
}

func TestNRPTGroupPolicyDisablesLocalRules(t *testing.T) {
	f := newFakeNRPT()
	n := testNRPT(f)
	if _, err := n.Apply([]string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	f.managed = true
	_, err := n.Apply([]string{"a.example.com"})
	if !errors.Is(err, ErrPolicyManaged) {
		t.Fatalf("Apply = %v, want ErrPolicyManaged", err)
	}
	if len(f.rules) != 0 || n.Active() != nil {
		t.Errorf("rules = %v, active = %v; want none while policy owns the table", f.rules, n.Active())
	}
}

func TestNRPTRejectsBadInput(t *testing.T) {
	f := newFakeNRPT()
	if _, err := testNRPT(f).Apply([]string{"../evil"}); err == nil {
		t.Error("an invalid domain was accepted")
	}
	if _, err := newNRPT(f, "127.0.0.1", 53053).Apply([]string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "port 53") {
		t.Errorf("Apply on a port the NRPT cannot carry = %v", err)
	}
	if _, err := newNRPT(f, "localhost", 53).Apply([]string{"a.example.com"}); err == nil {
		t.Error("a forwarder address that is not an IP was accepted")
	}
	if len(f.rules) != 0 {
		t.Errorf("rules = %v, want none", f.rules)
	}
	if err := newNRPT(f, "localhost", 53).RemoveAll(); err != nil {
		t.Errorf("RemoveAll on a misconfigured forwarder address = %v", err)
	}
}

func TestNRPTReloadFailureIsReportedAndRetried(t *testing.T) {
	f := newFakeNRPT()
	n := testNRPT(f)
	f.failReload = errors.New("service stopped")
	if _, err := n.Apply([]string{"a.example.com"}); err == nil {
		t.Fatal("Apply hid a failed reload")
	}
	if n.Active() != nil {
		t.Errorf("Active = %v after a failed reload", n.Active())
	}
	f.failReload = nil
	if _, err := n.Apply([]string{"a.example.com"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if f.reloads != 1 || len(n.Active()) != 1 {
		t.Errorf("reloads = %d, active = %v after the retry", f.reloads, n.Active())
	}
}

func TestNRPTWriteFailureKeepsGoodRulesAndReports(t *testing.T) {
	f := newFakeNRPT()
	f.failWrite = errors.New("access denied")
	n := testNRPT(f)
	if _, err := n.Apply([]string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("Apply = %v, want the write error", err)
	}
	if n.Active() != nil {
		t.Errorf("Active = %v with nothing written", n.Active())
	}
}
