//go:build !windows

package platform

// CheckFileSecurity does nothing here: Unix systems check the owner uid and
// mode bits where the file is read (config.ValidateConfigSecurity).
func CheckFileSecurity(string) error { return nil }
