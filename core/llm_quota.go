package core

import (
	"strconv"
	"sync"
	"time"
)

const llmQuotaReservationsStoreKey = "__pbLLMQuotaReservations__"

// llmQuotaReservations keeps track of the in-flight (aka. not logged yet)
// LLM requests so that concurrent requests couldn't bypass the quotas.
type llmQuotaReservations struct {
	mu       sync.Mutex
	inflight map[string]int
}

func getLLMQuotaReservations(app App) *llmQuotaReservations {
	v := app.Store().GetOrSet(llmQuotaReservationsStoreKey, func() any {
		return &llmQuotaReservations{inflight: map[string]int{}}
	})

	r, _ := v.(*llmQuotaReservations)

	return r
}

// LLMQuotaExceededError defines an exceeded LLM profile quota error.
type LLMQuotaExceededError struct {
	RetryAfter time.Duration
	Reason     string
}

// Error implements the [error] interface.
func (err *LLMQuotaExceededError) Error() string {
	return err.Reason
}

func llmQuotaWindowDuration(window string) time.Duration {
	switch window {
	case LLMQuotaWindowMinute:
		return time.Minute
	case LLMQuotaWindowDay:
		return 24 * time.Hour
	default:
		return time.Hour
	}
}

// ReserveLLMQuota checks the profile quotas of the provided actor
// (the per user quota of authRecord or, if nil, the per guest ip quota)
// and on success registers an in-flight reservation.
//
// The returned release function must be called once the request completes (and it is logged).
//
// Returns [*LLMQuotaExceededError] if the quota is exceeded.
func (app *BaseApp) ReserveLLMQuota(profile *LLMProfile, authRecord *Record, ip string) (func(), error) {
	noop := func() {}

	filter := LLMUsageFilter{Profile: profile.Name}

	var quota LLMQuota
	var key string
	if authRecord != nil {
		quota = profile.Quotas.PerUser
		filter.AuthCollection = authRecord.Collection().Id
		filter.AuthRecord = authRecord.Id
		key = profile.Name + "@" + filter.AuthCollection + "/" + filter.AuthRecord
	} else {
		quota = profile.Quotas.PerGuestIP
		filter.IP = ip
		key = profile.Name + "@ip:" + filter.IP
	}

	if !quota.IsEnabled() {
		return noop, nil
	}

	window := llmQuotaWindowDuration(quota.Window)
	now := time.Now()
	filter.Since = now.Add(-window)

	reservations := getLLMQuotaReservations(app)

	reservations.mu.Lock()
	defer reservations.mu.Unlock()

	usage, err := app.LLMUsage(filter)
	if err != nil {
		return noop, err
	}

	inflight := reservations.inflight[key]

	var reason string
	if quota.Requests > 0 && usage.Requests+inflight >= quota.Requests {
		reason = "requests quota exceeded (" + strconv.Itoa(quota.Requests) + " per " + quota.Window + ")"
	} else if quota.Tokens > 0 && usage.TotalTokens() >= quota.Tokens {
		reason = "tokens quota exceeded (" + strconv.Itoa(quota.Tokens) + " per " + quota.Window + ")"
	}

	if reason != "" {
		retryAfter := time.Second
		if !usage.Oldest.IsZero() {
			// the time until the oldest counted log leaves the sliding window
			if d := usage.Oldest.Time().Add(window).Sub(now); d > retryAfter {
				retryAfter = d
			}
		}

		return noop, &LLMQuotaExceededError{RetryAfter: retryAfter, Reason: reason}
	}

	reservations.inflight[key]++

	var once sync.Once

	return func() {
		once.Do(func() {
			reservations.mu.Lock()
			defer reservations.mu.Unlock()

			reservations.inflight[key]--
			if reservations.inflight[key] <= 0 {
				delete(reservations.inflight, key)
			}
		})
	}, nil
}
