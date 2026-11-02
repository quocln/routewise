package main

// Build identity, set with -ldflags "-X main.Version=... -X main.Commit=...
// -X main.BuildTime=..." (see the Makefile). A binary built without them is a
// development build.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// environment is the label error reports carry: a build without a version is
// not a release.
func environment() string {
	if Version == "dev" {
		return "development"
	}
	return "production"
}
