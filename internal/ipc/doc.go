// Package ipc is the local transport between the helper and its clients (the
// app and the CLI): where the endpoint lives, how the helper listens on it with
// access limited to the machine's users, how a client connects, and how the
// helper learns who is on the other end of a connection. The JSON-RPC framing
// above it is the same on every platform; only the transport differs.
//
// macOS uses a Unix socket whose file mode and group (staff) are the access
// control, and reads the peer's uid from the kernel. Linux uses a world-
// connectable Unix socket and reads the peer's uid with SO_PEERCRED; the
// daemon's authorizer decides who may change routing. Windows uses the named
// pipe \\.\pipe\routewise (go-winio) with a DACL that admits authenticated
// local users, refuses remote clients, and reads the client's token for its
// identity. Other platforms report platform.ErrUnsupported.
package ipc
