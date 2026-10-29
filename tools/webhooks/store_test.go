package webhooks_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

func newDeliveries(n int, nextAttemptAt time.Time) []*webhooks.Delivery {
	result := make([]*webhooks.Delivery, n)
	for i := range n {
		result[i] = &webhooks.Delivery{
			Id:             "d" + strconv.Itoa(i),
			SubscriptionId: "s1",
			Event:          webhooks.Event{Id: "e" + strconv.Itoa(i), Topic: "a.b"},
			NextAttemptAt:  nextAttemptAt,
		}
	}
	return result
}

func TestMemoryStoreEnqueue(t *testing.T) {
	t.Parallel()

	s := webhooks.NewMemoryStore()
	ctx := context.Background()

	if err := s.Enqueue(ctx, &webhooks.Delivery{}); err == nil {
		t.Fatal("Expected missing id error")
	}

	if err := s.Enqueue(ctx, newDeliveries(2, time.Time{})...); err != nil {
		t.Fatal(err)
	}

	if err := s.Enqueue(ctx, newDeliveries(1, time.Time{})...); err == nil {
		t.Fatal("Expected duplicated id error")
	}

	all := s.All()
	if len(all) != 2 {
		t.Fatalf("Expected 2 deliveries, got %d", len(all))
	}

	for _, d := range all {
		if d.Status != webhooks.StatusPending || d.Created.IsZero() {
			t.Fatalf("Expected pending delivery with created date, got %#v", d)
		}
	}
}

func TestMemoryStoreClaimDueAndLease(t *testing.T) {
	t.Parallel()

	s := webhooks.NewMemoryStore()
	ctx := context.Background()
	now := time.Now()

	items := newDeliveries(5, now.Add(-time.Second))
	items[4].NextAttemptAt = now.Add(time.Hour) // not due yet
	if err := s.Enqueue(ctx, items...); err != nil {
		t.Fatal(err)
	}

	claimed, err := s.ClaimDue(ctx, now, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 3 {
		t.Fatalf("Expected 3 claimed, got %d", len(claimed))
	}
	for _, d := range claimed {
		if d.LeaseToken == "" || !d.LeaseUntil.Equal(now.Add(time.Minute)) {
			t.Fatalf("Expected leased delivery, got %#v", d)
		}
	}

	// the leased ones shouldn't be claimed again
	claimed2, _ := s.ClaimDue(ctx, now, 10, time.Minute)
	if len(claimed2) != 1 || claimed2[0].Id != "d3" {
		t.Fatalf("Expected only d3 to be claimed, got %v", claimed2)
	}

	// limit 0
	if c, _ := s.ClaimDue(ctx, now, 0, time.Minute); len(c) != 0 {
		t.Fatalf("Expected nothing to be claimed with limit 0, got %d", len(c))
	}

	// after the lease expires it could be claimed again
	claimed3, _ := s.ClaimDue(ctx, now.Add(2*time.Minute), 10, time.Minute)
	if len(claimed3) != 4 {
		t.Fatalf("Expected 4 reclaimed deliveries after the lease expiration, got %d", len(claimed3))
	}

	// stale lease token
	stale := claimed[0]
	stale.Status = webhooks.StatusSuccess
	if err := s.MarkSuccess(ctx, stale, &webhooks.Attempt{}); !errors.Is(err, webhooks.ErrLeaseLost) {
		t.Fatalf("Expected ErrLeaseLost, got %v", err)
	}

	// valid lease token
	fresh := claimed3[0]
	fresh.Status = webhooks.StatusSuccess
	fresh.Attempts = 1
	if err := s.MarkSuccess(ctx, fresh, &webhooks.Attempt{StatusCode: 200}); err != nil {
		t.Fatal(err)
	}

	stored := s.Get(fresh.Id)
	if stored.Status != webhooks.StatusSuccess || stored.LeaseToken != "" || !stored.LeaseUntil.IsZero() || stored.Attempts != 1 {
		t.Fatalf("Unexpected stored delivery %#v", stored)
	}
	if len(s.Attempts(fresh.Id)) != 1 {
		t.Fatal("Expected 1 stored attempt")
	}

	// completed deliveries are not claimable
	for _, d := range claimed3[1:] {
		d.Status = webhooks.StatusDisabled
		if err := s.MarkDisabled(ctx, d, "test reason"); err != nil {
			t.Fatal(err)
		}
	}
	if s.Reason(claimed3[1].Id) != "test reason" {
		t.Fatal("Expected the disabled reason to be stored")
	}
	if c, _ := s.ClaimDue(ctx, now.Add(10*time.Minute), 10, time.Minute); len(c) != 0 {
		t.Fatalf("Expected no claimable deliveries, got %d", len(c))
	}

	if s.Get("missing") != nil {
		t.Fatal("Expected nil for missing delivery")
	}
}

func TestMemoryStoreConcurrentClaims(t *testing.T) {
	t.Parallel()

	s := webhooks.NewMemoryStore()
	ctx := context.Background()
	now := time.Now()

	if err := s.Enqueue(ctx, newDeliveries(100, time.Time{})...); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := map[string]int{}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				claimed, err := s.ClaimDue(ctx, now, 3, time.Hour)
				if err != nil {
					t.Error(err)
					return
				}
				if len(claimed) == 0 {
					return
				}
				mu.Lock()
				for _, d := range claimed {
					seen[d.Id]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != 100 {
		t.Fatalf("Expected 100 claimed deliveries, got %d", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("Delivery %s was claimed %d times", id, n)
		}
	}
}
