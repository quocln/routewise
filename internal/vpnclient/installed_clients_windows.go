package vpnclient

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// maxProductDepth bounds the walk of a product folder. The AWS VPN Client's
// OpenVPN sits at Service\Resources\openvpn.
const maxProductDepth = 5

func scanInstalled() []Client {
	var exes []string
	for _, root := range trustedClientRoots() {
		for _, product := range windowsProductDirs {
			exes = append(exes, productExecutables(filepath.Join(root, product))...)
		}
	}
	return installedWindowsClients(exes)
}

func productExecutables(dir string) []string {
	var exes []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(dir, path)
			if relErr == nil && strings.Count(rel, string(filepath.Separator)) >= maxProductDepth {
				return fs.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".exe") {
			exes = append(exes, path)
		}
		return nil
	})
	return exes
}

func resolveInstalled(path string) (Client, error) {
	// Links are followed first: the location that counts is the real one.
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Client{}, fmt.Errorf("%w: cannot read %q", ErrNotAVPNClient, path)
	}
	return resolveWindowsClient(real, trustedClientRoots(), scanInstalled())
}
