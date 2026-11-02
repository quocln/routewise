package main

import "context"

// followWaitMs is how long a follow request asks the helper to hold it for
// news before answering empty; the client allows that wait on top of its
// normal timeout.
const followWaitMs = 15000

// followLoop runs step until it fails or ctx ends. Each step is one long-poll
// round that prints what is new and remembers where to continue from.
func followLoop(ctx context.Context, step func(ctx context.Context) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(ctx); err != nil {
			return err
		}
	}
}

// verdictLabel is how activity, history and check name where traffic went.
func verdictLabel(viaVPN bool) string {
	if viaVPN {
		return "VPN"
	}
	return "DIRECT"
}
