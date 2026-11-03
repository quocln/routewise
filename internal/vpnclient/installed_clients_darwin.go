package vpnclient

func scanInstalled() []Client { return scanMac("/") }

func resolveInstalled(path string) (Client, error) { return resolveMacClient(path) }
