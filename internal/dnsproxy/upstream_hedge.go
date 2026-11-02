package dnsproxy

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// DefaultHedgeDelay is how long a query waits for an upstream before also asking
// the next server of its group. An upstream that fails moves on at once; this is
// for one that is merely slow or silently gone.
const DefaultHedgeDelay = 200 * time.Millisecond

// upstreamResult is what one upstream of a group said.
type upstreamResult struct {
	server string
	reply  *dns.Msg
	err    error
}

// askGroup asks the servers of one group for req, starting with the first, and
// also asks the next one whenever the servers asked so far have failed or stayed
// silent for the hedge delay. Only the servers of one group are ever asked: they
// are interchangeable, while a later group is a fallback that may not be allowed
// to see the name at all.
//
// A positive answer wins as soon as it arrives. A negative one (NXDOMAIN, or no
// records) is held until every server already asked has replied, because in a
// race the fastest reply is not the most informed: a server without the zone must
// not beat one that has it. Once a negative answer is held no further server is
// asked, so a server that answers NXDOMAIN before the hedge delay is final.
//
// answer is nil when no server gave a usable answer; failure is then the last
// SERVFAIL or REFUSED reply, if any.
func (f *Forwarder) askGroup(client *dns.Client, req *dns.Msg, servers []string) (answer, failure *dns.Msg) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Buffered for every server, so a query the decision no longer needs can
	// report its result and exit with nobody reading.
	results := make(chan upstreamResult, len(servers))
	timer := time.NewTimer(f.hedgeDelay)
	defer timer.Stop()

	next, inFlight := 0, 0
	askNext := func() {
		server := servers[next]
		next++
		inFlight++
		// Each exchange gets its own copy: they run at once and the client may
		// touch the message while packing it.
		query := req.Copy()
		go func() {
			reply, err := askUpstream(ctx, client, query, upstreamAddr(server))
			results <- upstreamResult{server: server, reply: reply, err: err}
		}()
		timer.Reset(f.hedgeDelay)
	}

	askNext()
	var negative *dns.Msg
	for inFlight > 0 {
		select {
		case <-timer.C:
			if negative == nil && next < len(servers) {
				askNext()
			}
		case r := <-results:
			inFlight--
			switch {
			case r.err != nil:
				f.logger.Debug("dns upstream failed", "server", r.server, "error", r.err)
			case r.reply.Rcode == dns.RcodeServerFailure || r.reply.Rcode == dns.RcodeRefused:
				failure = r.reply
			case isPositive(r.reply):
				return r.reply, nil
			default:
				if negative == nil {
					negative = r.reply
				}
				continue
			}
			// A failure frees its place at once instead of waiting out the
			// delay, unless a negative answer already settled the question.
			if negative == nil && next < len(servers) {
				askNext()
			}
		}
	}
	return negative, failure
}

// isPositive reports whether reply settles the question without waiting for any
// other server. A truncated reply counts: it tells the client to ask again over
// TCP, and holding it back would only delay that.
func isPositive(reply *dns.Msg) bool {
	return reply.Rcode == dns.RcodeSuccess && (len(reply.Answer) > 0 || reply.Truncated)
}

// askUpstream runs one exchange and abandons it when ctx ends. Closing the
// connection is what interrupts the wait: the library honours a context's
// deadline but not its cancellation, and a losing query must not hold its socket
// for the rest of the upstream timeout.
func askUpstream(ctx context.Context, client *dns.Client, req *dns.Msg, addr string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	reply, _, err := client.ExchangeWithConnContext(ctx, req, conn)
	return reply, err
}
