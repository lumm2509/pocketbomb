package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Store defines a persistent deliveries queue.
//
// Implementations must be safe for concurrent use and [Store.ClaimDue] must be
// atomic so that a single delivery couldn't be claimed by more than one worker
// while its lease is active.
//
// The Mark* methods receive the delivery with its already updated state
// (Status, Attempts, NextAttemptAt) and must persist it only if the delivery
// lease token still matches (otherwise [ErrLeaseLost] should be returned).
// On success the lease must be released.
type Store interface {
	// Enqueue persists the provided new deliveries.
	Enqueue(ctx context.Context, deliveries ...*Delivery) error

	// ClaimDue claims up to limit pending or retrying deliveries whose
	// NextAttemptAt is <= now and that are not currently leased.
	//
	// The claimed deliveries are leased until now+leaseFor and
	// their LeaseUntil and LeaseToken fields are updated.
	ClaimDue(ctx context.Context, now time.Time, limit int, leaseFor time.Duration) ([]*Delivery, error)

	// MarkSuccess persists a successful delivery attempt.
	MarkSuccess(ctx context.Context, d *Delivery, a *Attempt) error

	// MarkFailure persists a failed delivery attempt
	// (d.Status is either [StatusRetrying] or [StatusFailed]).
	MarkFailure(ctx context.Context, d *Delivery, a *Attempt) error

	// MarkDisabled marks the delivery as [StatusDisabled] (aka. discarded without sending).
	MarkDisabled(ctx context.Context, d *Delivery, reason string) error
}

// NewLeaseToken generates a new random lease token.
func NewLeaseToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
