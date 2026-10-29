package webhooks_test

import (
	"slices"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

func TestRetryPolicyDefaultSchedule(t *testing.T) {
	t.Parallel()

	schedule := webhooks.DefaultRetryPolicy().Schedule()

	expected := []time.Duration{
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		16 * time.Minute,
		32 * time.Minute,
		64 * time.Minute,
		120 * time.Minute,
	}

	if !slices.Equal(schedule, expected) {
		t.Fatalf("Expected schedule\n%v\ngot\n%v", expected, schedule)
	}

	var total time.Duration
	for _, d := range schedule {
		total += d
	}
	if total < 4*time.Hour || total > 4*time.Hour+10*time.Minute {
		t.Fatalf("Expected ~4h total retries window, got %v", total)
	}
}

func TestRetryPolicyBackoff(t *testing.T) {
	t.Parallel()

	p := webhooks.RetryPolicy{
		MaxAttempts:  4,
		BaseInterval: time.Second,
		MaxInterval:  3 * time.Second,
		Multiplier:   2,
	}

	scenarios := []struct {
		attempts int
		delay    time.Duration
		retry    bool
	}{
		{0, 0, true},
		{1, time.Second, true},
		{2, 2 * time.Second, true},
		{3, 3 * time.Second, true}, // capped
		{4, 0, false},
		{5, 0, false},
	}

	for _, s := range scenarios {
		delay, retry := p.Backoff(s.attempts)
		if delay != s.delay || retry != s.retry {
			t.Errorf("[%d] Expected (%v, %v), got (%v, %v)", s.attempts, s.delay, s.retry, delay, retry)
		}
	}
}

func TestRetryPolicyJitter(t *testing.T) {
	t.Parallel()

	p := webhooks.RetryPolicy{
		MaxAttempts:  3,
		BaseInterval: time.Minute,
		Jitter:       0.1,
	}

	for i := 0; i < 100; i++ {
		delay, ok := p.Backoff(1)
		if !ok {
			t.Fatal("Expected retry")
		}
		if delay < 54*time.Second || delay > 66*time.Second {
			t.Fatalf("Delay %v is outside the jitter range", delay)
		}
	}
}

func TestRetryPolicyNormalize(t *testing.T) {
	t.Parallel()

	// zero policy should behave as the default one
	zero := webhooks.RetryPolicy{}
	if !slices.Equal(zero.Schedule(), webhooks.DefaultRetryPolicy().Schedule()) {
		t.Fatalf("Expected the zero policy to fallback to the defaults, got %v", zero.Schedule())
	}

	// single attempt
	single := webhooks.RetryPolicy{MaxAttempts: 1}
	if _, ok := single.Backoff(1); ok {
		t.Fatal("Expected no retries")
	}
}
