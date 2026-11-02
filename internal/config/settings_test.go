package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// notSettings are the Config fields with storage of their own.
var notSettings = []string{"domains", "vpns", "profiles"}

// scalarKeys walks Config the way the file format names its fields.
func scalarKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for field := range t.Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("mapstructure"), ",")
		if tag == "" || slices.Contains(notSettings, prefix+tag) {
			continue
		}
		if field.Type.Kind() == reflect.Struct {
			keys = append(keys, scalarKeys(field.Type, prefix+tag+".")...)
			continue
		}
		keys = append(keys, prefix+tag)
	}
	return keys
}

func TestEveryConfigFieldIsADeclaredSetting(t *testing.T) {
	declared := make([]string, 0, len(Settings))
	for _, s := range Settings {
		declared = append(declared, s.Key)
	}
	want := scalarKeys(reflect.TypeFor[Config](), "")
	slices.Sort(declared)
	slices.Sort(want)
	if !slices.Equal(declared, want) {
		t.Errorf("Settings = %v\nConfig has %v", declared, want)
	}
}

func TestEachSettingPointsAtItsOwnField(t *testing.T) {
	cfg := DefaultConfig()
	seen := map[any]string{}
	for _, s := range Settings {
		field := s.Field(cfg)
		if reflect.TypeOf(field).Kind() != reflect.Pointer {
			t.Fatalf("%s: Field must return a pointer", s.Key)
		}
		if other, dup := seen[field]; dup {
			t.Errorf("%s and %s point at the same field", s.Key, other)
		}
		seen[field] = s.Key
	}
}

func TestSettingFieldsWritesThroughToTheConfig(t *testing.T) {
	cfg := DefaultConfig()
	*SettingFields(cfg)["routing.allow_ipv6"].(*bool) = true
	if !cfg.Routing.AllowIPv6 {
		t.Error("the pointer must lead to the config's own field")
	}
}
