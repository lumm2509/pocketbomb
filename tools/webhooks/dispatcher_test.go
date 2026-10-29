package webhooks_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestDispatcherProcessDueSuccess(t *testing.T) {
	t.Parallel()

	store := webhooks.NewMemoryStore()
	ctx := context.Background()

	if err := store.Enqueue(ctx, newDeliveries(3, time.Time{})...); err != nil {
		t.Fatal(err)
	}

	var results atomic.Int32

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store: store,
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			return &webhooks.Attempt{StatusCode: 204}, nil
		},
		OnResult: func(d *webhooks.Delivery, a *webhooks.Attempt) {
			results.Add(1)
		},
	})

	n, err := d.ProcessDue(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("Expected 3 processed, got %d", n)
	}
	if results.Load() != 3 {
		t.Fatalf("Expected 3 OnResult calls, got %d", results.Load())
	}

	for _, item := range store.All() {
		if item.Status != webhooks.StatusSuccess || item.Attempts != 1 || !item.NextAttemptAt.IsZero() {
			t.Fatalf("Unexpected delivery state %#v", item)
		}
	}

	// nothing else to process
	if n, _ := d.ProcessDue(ctx, 10); n != 0 {
		t.Fatalf("Expected 0 processed, got %d", n)
	}
}

func TestDispatcherRetriesAndFinalFailure(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := webhooks.NewMemoryStore()
	ctx := context.Background()

	if err := store.Enqueue(ctx, newDeliveries(1, time.Time{})...); err != nil {
		t.Fatal(err)
	}

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store: store,
		Now:   clock.Now,
		RetryPolicy: webhooks.RetryPolicy{
			MaxAttempts:  3,
			BaseInterval: time.Minute,
		},
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			return nil, errors.New("connection refused")
		},
	})

	// 1st attempt
	if n, err := d.ProcessDue(ctx, 1); n != 1 || err != nil {
		t.Fatalf("Expected 1 processed, got %d (%v)", n, err)
	}
	item := store.Get("d0")
	if item.Status != webhooks.StatusRetrying || item.Attempts != 1 || !item.NextAttemptAt.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("Unexpected state after 1st attempt %#v", item)
	}
	if attempts := store.Attempts("d0"); len(attempts) != 1 || attempts[0].Error != "connection refused" {
		t.Fatalf("Expected the send error to be stored in the attempt, got %#v", attempts)
	}

	// not due yet
	if n, _ := d.ProcessDue(ctx, 1); n != 0 {
		t.Fatalf("Expected 0 processed before the next attempt time, got %d", n)
	}

	// 2nd attempt
	clock.Add(time.Minute)
	d.ProcessDue(ctx, 1)
	item = store.Get("d0")
	if item.Status != webhooks.StatusRetrying || item.Attempts != 2 || !item.NextAttemptAt.Equal(clock.Now().Add(2*time.Minute)) {
		t.Fatalf("Unexpected state after 2nd attempt %#v", item)
	}

	// 3rd (final) attempt
	clock.Add(2 * time.Minute)
	d.ProcessDue(ctx, 1)
	item = store.Get("d0")
	if item.Status != webhooks.StatusFailed || item.Attempts != 3 || !item.NextAttemptAt.IsZero() {
		t.Fatalf("Unexpected state after the final attempt %#v", item)
	}

	clock.Add(time.Hour)
	if n, _ := d.ProcessDue(ctx, 1); n != 0 {
		t.Fatalf("Expected no more attempts, got %d", n)
	}
}

func TestDispatcherDisabled(t *testing.T) {
	t.Parallel()

	store := webhooks.NewMemoryStore()
	ctx := context.Background()
	store.Enqueue(ctx, newDeliveries(1, time.Time{})...)

	var resultAttempt *webhooks.Attempt
	var resultCalled bool

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store: store,
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			return nil, errors.Join(webhooks.ErrDisabled, errors.New("subscription deleted"))
		},
		OnResult: func(d *webhooks.Delivery, a *webhooks.Attempt) {
			resultCalled = true
			resultAttempt = a
		},
	})

	d.ProcessDue(ctx, 1)

	item := store.Get("d0")
	if item.Status != webhooks.StatusDisabled || item.Attempts != 0 {
		t.Fatalf("Unexpected state %#v", item)
	}
	if !resultCalled || resultAttempt != nil {
		t.Fatalf("Expected OnResult to be called with nil attempt")
	}
	if reason := store.Reason("d0"); reason == "" {
		t.Fatal("Expected disabled reason")
	}
}

func TestDispatcherDeliverWithLostLease(t *testing.T) {
	t.Parallel()

	store := webhooks.NewMemoryStore()
	ctx := context.Background()
	store.Enqueue(ctx, newDeliveries(1, time.Time{})...)

	var errorsCount atomic.Int32

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store: store,
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			return &webhooks.Attempt{StatusCode: 200}, nil
		},
		OnError: func(err error) {
			errorsCount.Add(1)
		},
	})

	claimed, _ := store.ClaimDue(ctx, time.Now(), 1, time.Minute)
	claimed[0].LeaseToken = "invalid"

	_, err := d.Deliver(ctx, claimed[0])
	if !errors.Is(err, webhooks.ErrLeaseLost) {
		t.Fatalf("Expected ErrLeaseLost, got %v", err)
	}
	if errorsCount.Load() != 1 {
		t.Fatalf("Expected OnError to be called once, got %d", errorsCount.Load())
	}
}

func TestDispatcherBackgroundWorkersConcurrency(t *testing.T) {
	t.Parallel()

	const total = 30
	const workers = 3

	store := webhooks.NewMemoryStore()
	ctx := context.Background()
	store.Enqueue(ctx, newDeliveries(total, time.Time{})...)

	var current, maxConcurrent atomic.Int32
	var mu sync.Mutex
	sent := map[string]int{}

	done := make(chan struct{})
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := current.Add(1)
		for {
			m := maxConcurrent.Load()
			if c <= m || maxConcurrent.CompareAndSwap(m, c) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		current.Add(-1)

		mu.Lock()
		sent[r.Header.Get(webhooks.HeaderWebhookId)]++
		if len(sent) == total {
			once.Do(func() { close(done) })
		}
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := webhooks.NewClient(webhooks.ClientOptions{AllowPrivateTargets: true})

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store:        store,
		Workers:      workers,
		PollInterval: time.Hour, // rely only on the initial loop and the workers notifications
		Send: client.SendFunc(func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Request, error) {
			return webhooks.NewRequest(d, srv.URL, "secret", ""), nil
		}),
	})

	d.Start()
	d.Start() // no-op

	if !d.IsRunning() {
		t.Fatal("Expected the dispatcher to be running")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for all deliveries")
	}

	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if d.IsRunning() {
		t.Fatal("Expected the dispatcher to be stopped")
	}

	if m := maxConcurrent.Load(); m > workers {
		t.Fatalf("Expected max %d concurrent requests, got %d", workers, m)
	}

	for id, n := range sent {
		if n != 1 {
			t.Fatalf("Delivery %s was sent %d times", id, n)
		}
	}

	for _, item := range store.All() {
		if item.Status != webhooks.StatusSuccess {
			t.Fatalf("Expected all deliveries to be successful, got %#v", item)
		}
	}
}

func TestDispatcherNotifyAndPaused(t *testing.T) {
	t.Parallel()

	store := webhooks.NewMemoryStore()
	ctx := context.Background()

	var paused atomic.Bool
	paused.Store(true)

	sentCh := make(chan string, 10)

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store:        store,
		PollInterval: time.Hour,
		Paused:       paused.Load,
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			sentCh <- d.Id
			return &webhooks.Attempt{StatusCode: 200}, nil
		},
	})
	d.Start()
	defer d.Close(context.Background())

	store.Enqueue(ctx, newDeliveries(1, time.Time{})...)
	d.Notify()

	select {
	case id := <-sentCh:
		t.Fatalf("Expected no sends while paused, got %s", id)
	case <-time.After(100 * time.Millisecond):
	}

	paused.Store(false)
	d.Notify()

	select {
	case id := <-sentCh:
		if id != "d0" {
			t.Fatalf("Expected d0, got %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Expected the delivery to be sent after Notify")
	}
}

func TestDispatcherCloseTimeoutLeavesLeased(t *testing.T) {
	t.Parallel()

	store := webhooks.NewMemoryStore()
	ctx := context.Background()
	store.Enqueue(ctx, newDeliveries(1, time.Time{})...)

	started := make(chan struct{})

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store:        store,
		PollInterval: time.Hour,
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			close(started)
			<-ctx.Done() // simulate a hanging request
			return &webhooks.Attempt{Error: ctx.Err().Error()}, nil
		},
	})
	d.Start()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("The delivery was not started")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := d.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected DeadlineExceeded, got %v", err)
	}

	item := store.Get("d0")
	if item.Status != webhooks.StatusPending || item.Attempts != 0 || item.LeaseToken == "" {
		t.Fatalf("Expected the delivery to remain pending and leased, got %#v", item)
	}

	// restart and reclaim after the lease expiration
	sent := make(chan struct{}, 1)
	d2 := webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store: store,
		Now:   func() time.Time { return time.Now().Add(webhooks.DefaultLeaseDuration + time.Second) },
		Send: func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
			sent <- struct{}{}
			return &webhooks.Attempt{StatusCode: 200}, nil
		},
	})
	if n, err := d2.ProcessDue(ctx, 1); n != 1 || err != nil {
		t.Fatalf("Expected the expired lease delivery to be reprocessed, got %d (%v)", n, err)
	}
	if store.Get("d0").Status != webhooks.StatusSuccess {
		t.Fatal("Expected success status")
	}
}

func TestDispatcherSetRetryPolicy(t *testing.T) {
	t.Parallel()

	d := webhooks.NewDispatcher(webhooks.DispatcherConfig{Store: webhooks.NewMemoryStore()})

	p := webhooks.RetryPolicy{MaxAttempts: 2}
	d.SetRetryPolicy(p)

	if d.RetryPolicy() != p {
		t.Fatalf("Expected %v, got %v", p, d.RetryPolicy())
	}

	if d.LeaseDuration() != webhooks.DefaultLeaseDuration {
		t.Fatalf("Expected default lease duration, got %v", d.LeaseDuration())
	}
}
