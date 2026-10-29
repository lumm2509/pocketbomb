package core

import (
	"time"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// WebhooksConfig defines the app outgoing webhooks settings.
type WebhooksConfig struct {
	// Enabled is the global webhooks kill switch.
	//
	// When disabled no new events are enqueued and the
	// dispatcher stops sending the already queued deliveries.
	Enabled bool `form:"enabled" json:"enabled"`

	// MaxAttempts is the max number of attempts of a single delivery (including the first one).
	MaxAttempts int `form:"maxAttempts" json:"maxAttempts"`

	// RetryBaseInterval is the delay (in seconds) after the first failed attempt
	// (the next delays grow exponentially).
	RetryBaseInterval int `form:"retryBaseInterval" json:"retryBaseInterval"`

	// RetryMaxInterval is the max delay (in seconds) between two attempts.
	RetryMaxInterval int `form:"retryMaxInterval" json:"retryMaxInterval"`

	// Timeout is the per-request timeout (in seconds).
	Timeout int `form:"timeout" json:"timeout"`

	// AllowPrivateTargets disables the SSRF protection and allows sending
	// webhooks to private, loopback and other reserved IP addresses.
	//
	// It is expected to be enabled only in development.
	AllowPrivateTargets bool `form:"allowPrivateTargets" json:"allowPrivateTargets"`

	// MaxDays is the retention (in days) of the completed deliveries log entries.
	MaxDays int `form:"maxDays" json:"maxDays"`

	// AutoDisableAfter specifies after how many consecutive failed events
	// (aka. deliveries that have exhausted all of their attempts) a
	// subscription should be automatically disabled.
	//
	// Set to 0 to never auto disable.
	AutoDisableAfter int `form:"autoDisableAfter" json:"autoDisableAfter"`
}

func newDefaultWebhooksConfig() WebhooksConfig {
	return WebhooksConfig{
		Enabled:           true,
		MaxAttempts:       webhooks.DefaultMaxAttempts,
		RetryBaseInterval: int(webhooks.DefaultBaseInterval / time.Second),
		RetryMaxInterval:  int(webhooks.DefaultMaxInterval / time.Second),
		Timeout:           int(webhooks.DefaultTimeout / time.Second),
		MaxDays:           7,
		AutoDisableAfter:  20,
	}
}

// Validate makes WebhooksConfig validatable by implementing [validation.Validatable] interface.
func (c WebhooksConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.MaxAttempts, validation.Required, validation.Min(1), validation.Max(25)),
		validation.Field(&c.RetryBaseInterval, validation.Required, validation.Min(1), validation.Max(86400)),
		validation.Field(&c.RetryMaxInterval, validation.Required, validation.Min(c.RetryBaseInterval), validation.Max(7*86400)),
		validation.Field(&c.Timeout, validation.Required, validation.Min(1), validation.Max(60)),
		validation.Field(&c.MaxDays, validation.Required, validation.Min(1), validation.Max(365)),
		validation.Field(&c.AutoDisableAfter, validation.Min(0), validation.Max(10000)),
	)
}

// RetryPolicy returns the webhooks retry policy based on the current config.
func (c WebhooksConfig) RetryPolicy() webhooks.RetryPolicy {
	return webhooks.RetryPolicy{
		MaxAttempts:  c.MaxAttempts,
		BaseInterval: time.Duration(c.RetryBaseInterval) * time.Second,
		MaxInterval:  time.Duration(c.RetryMaxInterval) * time.Second,
		Multiplier:   webhooks.DefaultMultiplier,
		Jitter:       webhooks.DefaultJitter,
	}
}

// ClientOptions returns the webhooks client options based on the current config.
func (c WebhooksConfig) ClientOptions() webhooks.ClientOptions {
	return webhooks.ClientOptions{
		Timeout:             time.Duration(c.Timeout) * time.Second,
		MaxResponseBodySize: webhooks.DefaultMaxResponseBodySize,
		AllowPrivateTargets: c.AllowPrivateTargets,
	}
}
