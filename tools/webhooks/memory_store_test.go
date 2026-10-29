package webhooks

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

var _ Store = (*MemoryStore)(nil)

// MemoryStore is an in-memory [Store] implementation (mainly for tests).
type MemoryStore struct {
	mu         sync.Mutex
	deliveries map[string]*Delivery
	order      []string
	attempts   map[string][]*Attempt
	reasons    map[string]string
}

// NewMemoryStore creates a new empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		deliveries: map[string]*Delivery{},
		attempts:   map[string][]*Attempt{},
		reasons:    map[string]string{},
	}
}

// Enqueue implements [Store.Enqueue].
func (s *MemoryStore) Enqueue(ctx context.Context, deliveries ...*Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, d := range deliveries {
		if d.Id == "" {
			return errors.New("webhooks: missing delivery id")
		}
		if _, ok := s.deliveries[d.Id]; ok {
			return errors.New("webhooks: duplicated delivery id " + d.Id)
		}
	}

	now := time.Now()

	for _, d := range deliveries {
		clone := *d
		if clone.Status == "" {
			clone.Status = StatusPending
		}
		if clone.Created.IsZero() {
			clone.Created = now
		}
		clone.Updated = now
		s.deliveries[d.Id] = &clone
		s.order = append(s.order, d.Id)
	}

	return nil
}

// ClaimDue implements [Store.ClaimDue].
func (s *MemoryStore) ClaimDue(ctx context.Context, now time.Time, limit int, leaseFor time.Duration) ([]*Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := []*Delivery{}
	if limit <= 0 {
		return result, nil
	}

	for _, id := range s.order {
		d := s.deliveries[id]
		if d.Status != StatusPending && d.Status != StatusRetrying {
			continue
		}
		if d.NextAttemptAt.After(now) || d.LeaseUntil.After(now) {
			continue
		}

		d.LeaseUntil = now.Add(leaseFor)
		d.LeaseToken = NewLeaseToken()

		clone := *d
		result = append(result, &clone)

		if len(result) >= limit {
			break
		}
	}

	return result, nil
}

func (s *MemoryStore) update(d *Delivery, a *Attempt, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.deliveries[d.Id]
	if !ok {
		return errors.New("webhooks: missing delivery " + d.Id)
	}

	if existing.LeaseToken != d.LeaseToken {
		return ErrLeaseLost
	}

	clone := *d
	clone.LeaseToken = ""
	clone.LeaseUntil = time.Time{}
	clone.Updated = time.Now()
	s.deliveries[d.Id] = &clone

	if a != nil {
		s.attempts[d.Id] = append(s.attempts[d.Id], a)
	}

	if reason != "" {
		s.reasons[d.Id] = reason
	}

	return nil
}

// MarkSuccess implements [Store.MarkSuccess].
func (s *MemoryStore) MarkSuccess(ctx context.Context, d *Delivery, a *Attempt) error {
	return s.update(d, a, "")
}

// MarkFailure implements [Store.MarkFailure].
func (s *MemoryStore) MarkFailure(ctx context.Context, d *Delivery, a *Attempt) error {
	return s.update(d, a, "")
}

// MarkDisabled implements [Store.MarkDisabled].
func (s *MemoryStore) MarkDisabled(ctx context.Context, d *Delivery, reason string) error {
	return s.update(d, nil, reason)
}

// Get returns a copy of the stored delivery with the specified id (or nil if missing).
func (s *MemoryStore) Get(id string) *Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.deliveries[id]
	if !ok {
		return nil
	}

	clone := *d
	return &clone
}

// All returns a copy of all stored deliveries (in insertion order).
func (s *MemoryStore) All() []*Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Delivery, 0, len(s.order))
	for _, id := range s.order {
		clone := *s.deliveries[id]
		result = append(result, &clone)
	}

	return result
}

// Attempts returns the recorded attempts of the specified delivery.
func (s *MemoryStore) Attempts(id string) []*Attempt {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.attempts[id])
}

// Reason returns the disabled reason of the specified delivery (if any).
func (s *MemoryStore) Reason(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reasons[id]
}
