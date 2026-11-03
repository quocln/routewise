package vpnclient

func scanInstalled() []Client { return scanLinux("") }

func resolveInstalled(path string) (Client, error) { return resolveLinuxClient("", path) }
