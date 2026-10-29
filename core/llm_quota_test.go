package core_test

import (
	"errors"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestReserveLLMQuota(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	profile := &core.LLMProfile{
		Name: "quota_test",
		Quotas: core.LLMProfileQuotas{
			PerUser:    core.LLMQuota{Requests: 2, Window: core.LLMQuotaWindowHour},
			PerGuestIP: core.LLMQuota{Requests: 1, Window: core.LLMQuotaWindowHour},
		},
	}

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// guest: 1 in-flight request
	release, err := app.ReserveLLMQuota(profile, nil, "1.2.3.4")
	if err != nil {
		t.Fatalf("Expected the first guest reservation to succeed, got %v", err)
	}

	var quotaErr *core.LLMQuotaExceededError
	if _, err := app.ReserveLLMQuota(profile, nil, "1.2.3.4"); !errors.As(err, &quotaErr) || quotaErr.RetryAfter <= 0 {
		t.Fatalf("Expected LLMQuotaExceededError for the second in-flight guest request, got %v", err)
	}

	// another ip has its own quota
	if _, err := app.ReserveLLMQuota(profile, nil, "5.6.7.8"); err != nil {
		t.Fatalf("Expected another ip reservation to succeed, got %v", err)
	}

	release()
	release() // no-op

	if _, err := app.ReserveLLMQuota(profile, nil, "1.2.3.4"); err != nil {
		t.Fatalf("Expected the guest reservation to succeed after release, got %v", err)
	}

	// per user
	for i := 0; i < 2; i++ {
		if _, err := app.ReserveLLMQuota(profile, user, ""); err != nil {
			t.Fatalf("[%d] Expected the user reservation to succeed, got %v", i, err)
		}
	}
	if _, err := app.ReserveLLMQuota(profile, user, ""); !errors.As(err, &quotaErr) {
		t.Fatalf("Expected LLMQuotaExceededError for the third user request, got %v", err)
	}

	// disabled quota
	unlimited := &core.LLMProfile{Name: "unlimited"}
	for i := 0; i < 3; i++ {
		if _, err := app.ReserveLLMQuota(unlimited, nil, "1.2.3.4"); err != nil {
			t.Fatalf("[%d] Expected no quota, got %v", i, err)
		}
	}
}
