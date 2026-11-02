package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/dnswatch"
)

// maxQueuedAnswers bounds how many captured answers wait out their settle
// delay. An answer waits dnsAnswerSettle, so reaching the bound takes thousands
// of answers inside that time; beyond it an answer is not recorded in the
// activity log (its names are still remembered).
const maxQueuedAnswers = 8192

// answerQueue holds captured DNS answers until their settle delay has passed.
// One goroutine (run) releases them in arrival order, which is also due order
// because the delay is the same for all, so no answer owns a timer of its own
// and none can fire after the daemon stops.
type answerQueue struct {
	delay time.Duration
	now   func() time.Time

	mu    sync.Mutex
	items []queuedAnswer
	// wake tells run that the queue was empty and now is not.
	wake chan struct{}
}

type queuedAnswer struct {
	due    time.Time
	answer dnswatch.Answer
}

func newAnswerQueue(delay time.Duration) *answerQueue {
	return &answerQueue{delay: delay, now: time.Now, wake: make(chan struct{}, 1)}
}

// push queues a for release after the delay. It reports false when the queue is
// full and a was dropped.
func (q *answerQueue) push(a dnswatch.Answer) bool {
	q.mu.Lock()
	if len(q.items) >= maxQueuedAnswers {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, queuedAnswer{due: q.now().Add(q.delay), answer: a})
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// takeDue removes the answers whose delay has passed and returns them, with how
// long until the next one is due (negative when the queue is empty).
func (q *answerQueue) takeDue() (due []dnswatch.Answer, next time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	n := 0
	for n < len(q.items) && !q.items[n].due.After(now) {
		due = append(due, q.items[n].answer)
		n++
	}
	q.items = q.items[n:]
	if len(q.items) == 0 {
		q.items = nil
		return due, -1
	}
	return due, q.items[0].due.Sub(now)
}

// run releases answers to emit until ctx ends. Answers still waiting then are
// dropped.
func (q *answerQueue) run(ctx context.Context, emit func(dnswatch.Answer)) {
	for {
		due, next := q.takeDue()
		for _, a := range due {
			emit(a)
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if next >= 0 {
			timer = time.NewTimer(next)
			timeout = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-q.wake:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
