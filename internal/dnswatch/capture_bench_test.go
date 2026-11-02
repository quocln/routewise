package dnswatch

import (
	"encoding/binary"
	"testing"
)

// bpfRecord frames one packet the way a BPF read returns it.
func bpfRecord(frame []byte) []byte {
	const hdrLen = 18
	rec := make([]byte, (hdrLen+len(frame)+3)&^3)
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint16(rec[16:18], hdrLen)
	copy(rec[hdrLen:], frame)
	return rec
}

// BenchmarkHandleFrameTCPSYN is the common packet on the capture path: an
// outbound connection start.
func BenchmarkHandleFrameTCPSYN(b *testing.B) {
	w, _, _ := newTestWatcher("10.0.0.2")
	w.SetFlowHandler(func(Flow) {})
	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleFrame(syn, dltRaw, "en0")
	}
}

// BenchmarkHandleFrameIgnored is traffic the kernel filter passes that
// userspace discards: a SYN from an address that is not this Mac's.
func BenchmarkHandleFrameIgnored(b *testing.B) {
	w, _, _ := newTestWatcher("10.0.0.2")
	syn := ipv4Between("203.0.113.9", "10.0.0.2", 6, 0, 0, tcpSegment(22, flagSYN, nil))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleFrame(syn, dltRaw, "en0")
	}
}

func BenchmarkSplitBPFBuffer(b *testing.B) { benchSplit(b, false) }

// BenchmarkAppendBPFFramesReused is the read path: one frames slice kept
// across reads.
func BenchmarkAppendBPFFramesReused(b *testing.B) { benchSplit(b, true) }

func benchSplit(b *testing.B, reuse bool) {
	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	var buf []byte
	for i := 0; i < 16; i++ {
		buf = append(buf, bpfRecord(syn)...)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var frames [][]byte
	for i := 0; i < b.N; i++ {
		if reuse {
			frames = appendBPFFrames(frames[:0], buf)
		} else {
			splitBPFBuffer(buf)
		}
	}
}
