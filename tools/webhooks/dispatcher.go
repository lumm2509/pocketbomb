package webhooks

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Default dispatcher options.
const (
	DefaultWorkers      = 4
	DefaultPollInterval = 5 * time.Second
	// the lease should be long enough to cover a single attempt (incl. the hooks and store calls)
	DefaultLeaseDuration = 2 * time.Minute
)

// SendFunc performs a single delivery attempt.
//
// Returning an error wrapping [ErrDisabled] marks the delivery as [StatusDisabled]
// without counting it as attempt. Any other error is treated as failed attempt
// (the error message is stored in [Attempt.Error] if not already set).
type SendFunc func(ctx context.Context, d *Delivery) (*Attempt, error)

// ResolveFunc returns the request to send for the specified delivery
// (see [Client.SendFunc]).
type ResolveFunc func(ctx context.Context, d *Delivery) (*Request, error)

// SendFunc returns a simple [SendFunc] that sends the request
// returned by the resolve function with the current client.
func (c *Client) SendFunc(resolve ResolveFunc) SendFunc {
	return func(ctx context.Context, d *Delivery) (*Attempt, error) {
		req, err := resolve(ctx, d)
		if err != nil {
			return nil, err
		}

		return c.Send(ctx, req), nil
	}
}

// DispatcherConfig defines the [Dispatcher] configuration.
type DispatcherConfig struct {
	// Store is the deliveries queue (required).
	Store Store

	// Send performs a single delivery attempt (required).
	Send SendFunc

	// RetryPolicy is the initial retry policy (see also [Dispatcher.SetRetryPolicy]).
	RetryPolicy RetryPolicy

	// Workers is the max number of concurrent delivery attempts (default to [DefaultWorkers]).
	Workers int

	// PollInterval is the store polling interval (default to [DefaultPollInterval]).
	//
	// The dispatcher could be also woken up earlier with [Dispatcher.Notify].
	PollInterval time.Duration

	// LeaseDuration is the claimed deliveries lease duration (default to [DefaultLeaseDuration]).
	//
	// It must be longer than the max duration of a single attempt.
	LeaseDuration time.Duration

	// Paused is an optional function that reports whether the
	// dispatcher should skip claiming new deliveries (e.g. global kill switch).
	Paused func() bool

	// OnResult is an optional callback invoked after each processed delivery
	// with its updated state and the related attempt (nil for disabled deliveries).
	OnResult func(d *Delivery, a *Attempt)

	// OnError is an optional callback for the background store errors.
	OnError func(err error)

	// Now is an optional current time getter (mainly for tests).
	Now func() time.Time
}

// Dispatcher claims the due deliveries from a [Store] and sends them
// with a bounded worker pool.
//
// Delivery semantic is at-least-once: if the process dies (or the lease expires)
// during an attempt the delivery will be claimed and sent again, so receivers
// should dedupe by the [HeaderEventId] header.
type Dispatcher struct {
	cfg DispatcherConfig

	mu     sync.RWMutex
	policy RetryPolicy

	sem      chan struct{}
	notifyCh chan struct{}

	lifecycleMu sync.Mutex
	running     bool
	stopCh      chan struct{}
	loopDone    chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	inflight    sync.WaitGroup
}

// NewDispatcher creates a new (not started) dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = DefaultLeaseDuration
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dispatcher{
		cfg:      cfg,
		policy:   cfg.RetryPolicy,
		sem:      make(chan struct{}, cfg.Workers),
		notifyCh: make(chan struct{}, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// RetryPolicy returns the current retry policy.
func (d *Dispatcher) RetryPolicy() RetryPolicy {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.policy
}

// SetRetryPolicy replaces the dispatcher retry policy
// (it is applied for the next processed attempts).
func (d *Dispatcher) SetRetryPolicy(p RetryPolicy) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.policy = p
}

// LeaseDuration returns the configured claim lease duration.
func (d *Dispatcher) LeaseDuration() time.Duration {
	return d.cfg.LeaseDuration
}

// IsRunning reports whether the dispatcher polling loop is running.
func (d *Dispatcher) IsRunning() bool {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()

	return d.running
}

// Start starts the background polling loop (no-op if already started).
//
// A closed dispatcher could be started again.
func (d *Dispatcher) Start() {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()

	if d.running {
		return
	}

	if d.ctx.Err() != nil {
		d.ctx, d.cancel = context.WithCancel(context.Background())
	}

	d.running = true
	d.stopCh = make(chan struct{})
	d.loopDone = make(chan struct{})

	go d.loop(d.ctx, d.stopCh, d.loopDone)
}

// Notify wakes up the polling loop (e.g. after enqueuing new deliveries).
//
// It is safe to call it even if the dispatcher is not started.
func (d *Dispatcher) Notify() {
	select {
	case d.notifyCh <- struct{}{}:
	default:
	}
}

// Close stops claiming new deliveries and waits for the in-flight attempts to complete.
//
// If ctx is done before that, the in-flight attempts are canceled and their
// deliveries are left leased in the store (they will be claimed again after
// their lease expires, e.g. on the next start).
func (d *Dispatcher) Close(ctx context.Context) error {
	d.lifecycleMu.Lock()
	if d.running {
		close(d.stopCh)
		<-d.loopDone
		d.running = false
	}
	d.lifecycleMu.Unlock()

	done := make(chan struct{})
	go func() {
		d.inflight.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		d.cancel()
		<-done
		return ctx.Err()
	}
}

func (d *Dispatcher) loop(ctx context.Context, stopCh chan struct{}, loopDone chan struct{}) {
	defer close(loopDone)

	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	for {
		// claim as many deliveries as there are free workers
		for {
			claimed, ok := d.claimAndDispatch(ctx, stopCh)
			if !ok || claimed == 0 {
				break
			}
		}

		select {
		case <-stopCh:
			return
		case <-ticker.C:
		case <-d.notifyCh:
		}
	}
}

// claimAndDispatch claims and asynchronously dispatches the due deliveries.
//
// It blocks until at least one worker is free.
func (d *Dispatcher) claimAndDispatch(ctx context.Context, stopCh chan struct{}) (int, bool) {
	if d.cfg.Paused != nil && d.cfg.Paused() {
		return 0, false
	}

	// wait for a free worker
	select {
	case d.sem <- struct{}{}:
	case <-stopCh:
		return 0, false
	}

	// count the additional free workers
	free := 1
	for free < d.cfg.Workers {
		select {
		case d.sem <- struct{}{}:
			free++
			continue
		default:
		}
		break
	}

	claimed, err := d.cfg.Store.ClaimDue(ctx, d.cfg.Now(), free, d.cfg.LeaseDuration)
	if err != nil {
		d.reportError(err)
	}

	// release the unused workers
	for i := len(claimed); i < free; i++ {
		<-d.sem
	}

	for _, item := range claimed {
		d.inflight.Add(1)
		go func(item *Delivery) {
			defer func() {
				<-d.sem
				d.inflight.Done()
				// wake up the loop since a worker is free
				d.Notify()
			}()

			_, _ = d.process(ctx, item)
		}(item)
	}

	return len(claimed), err == nil
}

// ProcessDue synchronously claims and processes up to limit due deliveries
// (it doesn't require the dispatcher to be started).
//
// It is useful mainly for tests and manual triggers.
func (d *Dispatcher) ProcessDue(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = d.cfg.Workers
	}

	claimed, err := d.cfg.Store.ClaimDue(ctx, d.cfg.Now(), limit, d.cfg.LeaseDuration)
	if err != nil {
		return 0, err
	}

	var wg sync.WaitGroup
	errs := make([]error, len(claimed))

	for i, item := range claimed {
		wg.Add(1)
		d.sem <- struct{}{}
		go func(i int, item *Delivery) {
			defer func() {
				<-d.sem
				wg.Done()
			}()

			_, errs[i] = d.process(ctx, item)
		}(i, item)
	}

	wg.Wait()

	return len(claimed), errors.Join(errs...)
}

// Deliver synchronously processes a single already leased delivery
// (aka. d.LeaseToken must match the stored one), e.g. a manual redelivery.
//
// Returns the attempt (nil for disabled deliveries) and the store error (if any).
func (d *Dispatcher) Deliver(ctx context.Context, delivery *Delivery) (*Attempt, error) {
	return d.process(ctx, delivery)
}

func (d *Dispatcher) process(ctx context.Context, delivery *Delivery) (*Attempt, error) {
	attempt, sendErr := d.cfg.Send(ctx, delivery)

	// the dispatcher was force closed (or the caller context was canceled) -
	// leave the delivery leased so that it could be claimed again after the lease expires
	if err := ctx.Err(); err != nil {
		return attempt, err
	}

	// the store updates shouldn't be affected by the caller cancellation
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	var storeErr error

	if errors.Is(sendErr, ErrDisabled) {
		delivery.Status = StatusDisabled
		delivery.NextAttemptAt = time.Time{}
		storeErr = d.cfg.Store.MarkDisabled(storeCtx, delivery, sendErr.Error())
		attempt = nil
	} else {
		if attempt == nil {
			attempt = &Attempt{StartedAt: d.cfg.Now()}
		}
		if sendErr != nil && attempt.Error == "" {
			attempt.Error = sendErr.Error()
		}

		delivery.Attempts++

		if attempt.Succeeded() {
			delivery.Status = StatusSuccess
			delivery.NextAttemptAt = time.Time{}
			storeErr = d.cfg.Store.MarkSuccess(storeCtx, delivery, attempt)
		} else {
			delay, retry := d.RetryPolicy().Backoff(delivery.Attempts)
			if retry {
				delivery.Status = StatusRetrying
				delivery.NextAttemptAt = d.cfg.Now().Add(delay)
			} else {
				delivery.Status = StatusFailed
				delivery.NextAttemptAt = time.Time{}
			}
			storeErr = d.cfg.Store.MarkFailure(storeCtx, delivery, attempt)
		}
	}

	if storeErr != nil {
		d.reportError(storeErr)
		return attempt, storeErr
	}

	if d.cfg.OnResult != nil {
		d.cfg.OnResult(delivery, attempt)
	}

	return attempt, nil
}

func (d *Dispatcher) reportError(err error) {
	if err != nil && d.cfg.OnError != nil {
		d.cfg.OnError(err)
	}
}
