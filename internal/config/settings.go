package config

import "reflect"

// Setting is one scalar setting of the configuration. This table is where a setting
// is declared: the database stores it under Key, and a YAML file gets its default
// from it. Domain lists, VPN clients and profiles are not settings: they have tables
// of their own.
type Setting struct {
	Key string
	// Field returns a pointer to the setting's value in cfg.
	Field func(cfg *Config) any
}

// Settings lists every setting. A test keeps it in step with the Config struct, so a
// new field that is not listed here fails before it can be lost at the next restart.
var Settings = []Setting{
	{"dns.servers", func(c *Config) any { return &c.DNS.Servers }},
	{"dns.cache_ttl", func(c *Config) any { return &c.DNS.CacheTTL }},
	{"dns.use_vpn_dns", func(c *Config) any { return &c.DNS.UseVPNDNS }},
	{"routing.mode", func(c *Config) any { return &c.Routing.Mode }},
	{"routing.allow_ipv6", func(c *Config) any { return &c.Routing.AllowIPv6 }},
	{"routing.default_vpn", func(c *Config) any { return &c.Routing.DefaultVPN }},
	{"routing.default_vpn_fallback", func(c *Config) any { return &c.Routing.DefaultVPNFallback }},
	{"routing.default_vpn_except", func(c *Config) any { return &c.Routing.DefaultVPNExcept }},
	{"daemon.poll_interval", func(c *Config) any { return &c.Daemon.PollInterval }},
	{"daemon.pid_file", func(c *Config) any { return &c.Daemon.PidFile }},
	{"daemon.log_file", func(c *Config) any { return &c.Daemon.LogFile }},
	{"daemon.log_level", func(c *Config) any { return &c.Daemon.LogLevel }},
	{"history.enabled", func(c *Config) any { return &c.History.Enabled }},
	{"history.retention_days", func(c *Config) any { return &c.History.RetentionDays }},
	{"telemetry.dsn", func(c *Config) any { return &c.Telemetry.DSN }},
	{"telemetry.errors", func(c *Config) any { return &c.Telemetry.Errors }},
	{"telemetry.sessions", func(c *Config) any { return &c.Telemetry.Sessions }},
	{"telemetry.logs", func(c *Config) any { return &c.Telemetry.Logs }},
	{"telemetry.traces", func(c *Config) any { return &c.Telemetry.Traces }},
	{"telemetry.traces_sample_rate", func(c *Config) any { return &c.Telemetry.TracesSampleRate }},
}

// SettingFields maps each setting's key to its value in cfg.
func SettingFields(cfg *Config) map[string]any {
	fields := make(map[string]any, len(Settings))
	for _, s := range Settings {
		fields[s.Key] = s.Field(cfg)
	}
	return fields
}

// settingValue is the value a pointer from Setting.Field points at.
func settingValue(field any) any {
	return reflect.ValueOf(field).Elem().Interface()
}
