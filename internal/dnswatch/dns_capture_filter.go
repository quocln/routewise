package dnswatch

import (
	"fmt"

	"golang.org/x/net/bpf"
)

const (
	// snapLen is how much of a DNS answer the kernel hands over: enough for
	// any UDP DNS answer.
	snapLen = 65535
	// flowSnapLen is how much of a connection-start packet the kernel hands
	// over. Only the headers matter: link (at most 14) + IPv4 with options
	// (at most 60) + the TCP flags byte, or IPv6 (40) + the UDP header and
	// first payload byte.
	flowSnapLen = 128

	tcpSYN = 0x02
	tcpACK = 0x10
	// quicLongHeader is the top bit of a QUIC packet's first byte. Only the
	// packets that set a connection up use the long header; established
	// traffic uses the short header, which has the bit clear.
	quicLongHeader = 0x80
)

// filterStep is one BPF instruction whose jumps name labels instead of
// counting instructions, so the program can be read and changed safely.
type filterStep struct {
	label string
	ins   bpf.Instruction
	// onTrue and onFalse are the labels a JumpIf continues at; "" falls
	// through to the next step. A bpf.Jump uses onTrue.
	onTrue, onFalse string
}

// assembleSteps resolves labels to the relative jumps BPF needs.
func assembleSteps(steps []filterStep) ([]bpf.Instruction, error) {
	at := make(map[string]int, len(steps))
	for i, s := range steps {
		if s.label == "" {
			continue
		}
		if _, dup := at[s.label]; dup {
			return nil, fmt.Errorf("duplicate label %q", s.label)
		}
		at[s.label] = i
	}
	skip := func(from int, label string) (uint32, error) {
		if label == "" {
			return 0, nil
		}
		to, ok := at[label]
		if !ok || to <= from {
			return 0, fmt.Errorf("label %q is not ahead of step %d", label, from)
		}
		return uint32(to - from - 1), nil
	}
	out := make([]bpf.Instruction, len(steps))
	for i, s := range steps {
		t, err := skip(i, s.onTrue)
		if err != nil {
			return nil, err
		}
		f, err := skip(i, s.onFalse)
		if err != nil {
			return nil, err
		}
		switch ins := s.ins.(type) {
		case bpf.JumpIf:
			if t > 255 || f > 255 {
				return nil, fmt.Errorf("jump at step %d is too long", i)
			}
			ins.SkipTrue, ins.SkipFalse = uint8(t), uint8(f)
			out[i] = ins
		case bpf.Jump:
			ins.Skip = t
			out[i] = ins
		default:
			out[i] = s.ins
		}
	}
	return out, nil
}

// captureFilter is the kernel-side filter. It accepts, over IPv4 (unfragmented
// or a first fragment, options allowed) and IPv6 (without extension headers):
//
//   - UDP from source port 53: DNS answers, handed over whole;
//   - TCP with SYN set and ACK clear: a connection being opened;
//   - UDP whose first payload byte has 0x80 set: a QUIC long header, which
//     only occurs while a connection is being set up.
//
// Established-flow TCP, non-initial QUIC and everything else is dropped in the
// kernel, so ordinary traffic never reaches RouteWise. linkLen is how many
// bytes precede the IP header.
func captureFilter(linkLen uint32) []bpf.Instruction {
	l := linkLen
	jeq := func(v uint32) bpf.JumpIf { return bpf.JumpIf{Cond: bpf.JumpEqual, Val: v} }
	jset := func(v uint32) bpf.JumpIf { return bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: v} }
	steps := []filterStep{
		{ins: bpf.LoadAbsolute{Off: l, Size: 1}},
		{ins: bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4}}, // IP version
		{ins: jeq(4), onFalse: "v6"},

		// IPv4
		{ins: bpf.LoadAbsolute{Off: l + 9, Size: 1}}, // protocol
		{ins: jeq(6), onTrue: "v4tcp"},
		{ins: jeq(17), onFalse: "drop"},
		// v4udp
		{ins: bpf.LoadAbsolute{Off: l + 6, Size: 2}},                 // flags and fragment offset
		{ins: jset(0x1fff), onTrue: "drop"},                          // a later fragment has no UDP header
		{ins: bpf.LoadMemShift{Off: l}},                              // X = IPv4 header length
		{ins: bpf.LoadIndirect{Off: l, Size: 2}},                     // UDP source port
		{ins: jeq(53), onTrue: "dns"},                                //
		{ins: bpf.LoadIndirect{Off: l + 8, Size: 1}},                 // first UDP payload byte
		{ins: jset(quicLongHeader), onTrue: "flow", onFalse: "drop"}, //
		{label: "v4tcp", ins: bpf.LoadAbsolute{Off: l + 6, Size: 2}}, // flags and fragment offset
		{ins: jset(0x1fff), onTrue: "drop"},                          // a later fragment has no TCP header
		{ins: bpf.LoadMemShift{Off: l}},                              // X = IPv4 header length
		{ins: bpf.LoadIndirect{Off: l + 13, Size: 1}},                // TCP flags
		{ins: bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: tcpSYN | tcpACK}},
		{ins: jeq(tcpSYN), onTrue: "flow", onFalse: "drop"},

		// IPv6, without extension headers
		{label: "v6", ins: jeq(6), onFalse: "drop"},
		{ins: bpf.LoadAbsolute{Off: l + 6, Size: 1}}, // next header
		{ins: jeq(6), onTrue: "v6tcp"},
		{ins: jeq(17), onFalse: "drop"},
		// v6udp
		{ins: bpf.LoadAbsolute{Off: l + 40, Size: 2}}, // UDP source port
		{ins: jeq(53), onTrue: "dns"},
		{ins: bpf.LoadAbsolute{Off: l + 48, Size: 1}}, // first UDP payload byte
		{ins: jset(quicLongHeader), onTrue: "flow", onFalse: "drop"},
		{label: "v6tcp", ins: bpf.LoadAbsolute{Off: l + 40 + 13, Size: 1}}, // TCP flags
		{ins: bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: tcpSYN | tcpACK}},
		{ins: jeq(tcpSYN), onTrue: "flow", onFalse: "drop"},

		{label: "dns", ins: bpf.RetConstant{Val: snapLen}},
		{label: "flow", ins: bpf.RetConstant{Val: flowSnapLen}},
		{label: "drop", ins: bpf.RetConstant{Val: 0}},
	}
	program, err := assembleSteps(steps)
	if err != nil {
		// The program is a constant: an error here is a programming mistake
		// that the filter tests catch.
		panic("dnswatch: capture filter: " + err.Error())
	}
	return program
}
