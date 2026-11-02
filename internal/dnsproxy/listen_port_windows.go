//go:build windows

package dnsproxy

// ListenPort is 53 on Windows: the Name Resolution Policy Table names a DNS
// server by address only, so the forwarder must answer on the standard port.
const ListenPort = 53

// FallbackHosts are the other loopback hosts to try when 127.0.0.1:53 is taken
// by another local DNS service. Windows treats all of 127.0.0.0/8 as loopback.
var FallbackHosts = []string{"127.0.0.53"}
