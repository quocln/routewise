//go:build !darwin && !linux && !windows

package dnswatch

import "github.com/quocln/routewise/internal/platform"

// Packet capture is implemented for macOS and Linux only. Other platforms build so the
// parsing code can be vetted and tested, and capture nothing.

var errCaptureUnsupported = platform.Unsupported("packet capture")

func openCapture(string) (*capture, error) { return nil, errCaptureUnsupported }

func (c *capture) read() ([][]byte, error) { return nil, errCaptureUnsupported }

func (c *capture) kernelDrops() (uint64, error) { return 0, errCaptureUnsupported }

func (c *capture) close() {}
