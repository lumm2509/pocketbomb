package webhooks

import (
	"math"
	"math/rand/v2"
	"time"
)

// Default retry policy values.
//
// With the defaults a delivery is attempted 8 times in total and the delays between
// the attempts are 2m, 4m, 8m, 16m, 32m, 64m, 120m (aka. ~4h06m), similar to Shopify.
const (
	DefaultMaxAttempts  = 8
	DefaultBaseInterval = 2 * time.Minute
	DefaultMaxInterval  = 2 * time.Hour
	DefaultMultiplier   = 2.0
	DefaultJitter       = 0.1
)

// RetryPolicy defines an exponential backoff retry policy.
type RetryPolicy struct {
	// MaxAttempts is the max number of attempts of a single delivery (including the first one).
	//
	// Zero or negative value fallbacks to [DefaultMaxAttempts].
	MaxAttempts int

	// BaseInterval is the delay after the first failed attempt.
	//
	// Zero or negative value fallbacks to [DefaultBaseInterval].
	BaseInterval time.Duration

	// MaxInterval caps the delay between two attempts.
	//
	// Zero or negative value fallbacks to [DefaultMaxInterval].
	MaxInterval time.Duration

	// Multiplier is the exponential growth factor (values < 1 fallback to [DefaultMultiplier]).
	Multiplier float64

	// Jitter is the random delay deviation ratio in the range [0, 1)
	// (e.g. 0.1 means ±10%) to avoid thundering herd.
	Jitter float64
}

// DefaultRetryPolicy returns the default retry policy.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:  DefaultMaxAttempts,
		BaseInterval: DefaultBaseInterval,
		MaxInterval:  DefaultMaxInterval,
		Multiplier:   DefaultMultiplier,
		Jitter:       DefaultJitter,
	}
}

func (p RetryPolicy) normalize() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultMaxAttempts
	}
	if p.BaseInterval <= 0 {
		p.BaseInterval = DefaultBaseInterval
	}
	if p.MaxInterval <= 0 {
		p.MaxInterval = DefaultMaxInterval
	}
	if p.MaxInterval < p.BaseInterval {
		p.MaxInterval = p.BaseInterval
	}
	if p.Multiplier < 1 {
		p.Multiplier = DefaultMultiplier
	}
	if p.Jitter < 0 || p.Jitter >= 1 {
		p.Jitter = 0
	}
	return p
}

// Backoff returns the delay before the next attempt after the specified
// number of already made (and failed) attempts.
//
// The second returned value reports whether another attempt is allowed.
func (p RetryPolicy) Backoff(attempts int) (time.Duration, bool) {
	p = p.normalize()

	if attempts < 1 {
		return 0, true
	}

	if attempts >= p.MaxAttempts {
		return 0, false
	}

	delay := float64(p.BaseInterval) * math.Pow(p.Multiplier, float64(attempts-1))
	if delay > float64(p.MaxInterval) || math.IsInf(delay, 0) || math.IsNaN(delay) {
		delay = float64(p.MaxInterval)
	}

	if p.Jitter > 0 {
		delay += delay * p.Jitter * (rand.Float64()*2 - 1)
	}

	return time.Duration(delay), true
}

// Schedule returns the list of the delays between all attempts (without jitter).
func (p RetryPolicy) Schedule() []time.Duration {
	p = p.normalize()
	p.Jitter = 0

	result := make([]time.Duration, 0, p.MaxAttempts-1)
	for i := 1; ; i++ {
		d, ok := p.Backoff(i)
		if !ok {
			break
		}
		result = append(result, d)
	}

	return result
}
