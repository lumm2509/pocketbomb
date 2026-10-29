package core

import (
	"github.com/lumm2509/pocketbomb/tools/types"
)

var _ Model = (*LLMLog)(nil)

// LLMLogsTableName is the auxiliary db table name of the LLM usage logs.
const LLMLogsTableName = "_llmLogs"

// LLMLog statuses.
const (
	// LLMLogStatusSuccess is a successfully completed provider call.
	LLMLogStatusSuccess = "success"

	// LLMLogStatusError is a failed provider call.
	LLMLogStatusError = "error"

	// LLMLogStatusDenied is a request rejected by the profile rule, the profile limits or an app hook
	// (the provider was not called).
	LLMLogStatusDenied = "denied"

	// LLMLogStatusLimited is a request rejected because of exceeded profile quota
	// (the provider was not called).
	LLMLogStatusLimited = "limited"
)

// LLMLog defines a single LLM call usage log entry.
type LLMLog struct {
	BaseModel

	Created types.DateTime `db:"created" json:"created"`

	// Provider is the name of the resolved provider config.
	Provider string `db:"provider" json:"provider"`

	// Model is the requested (or the provider reported) model.
	Model string `db:"model" json:"model"`

	// Profile is the name of the LLM profile (if any).
	Profile string `db:"profile" json:"profile"`

	Stream bool   `db:"stream" json:"stream"`
	Status string `db:"status" json:"status"`
	Error  string `db:"error" json:"error"`

	InputTokens  int `db:"inputTokens" json:"inputTokens"`
	OutputTokens int `db:"outputTokens" json:"outputTokens"`
	DurationMs   int `db:"durationMs" json:"durationMs"`

	// Request and Response are the serialized LLM request and response
	// (stored only if the content storage is enabled).
	Request  types.JSONRaw `db:"request" json:"request"`
	Response types.JSONRaw `db:"response" json:"response"`

	// AuthCollection and AuthRecord are the ids of the
	// authenticated caller collection and record (if any).
	AuthCollection string `db:"authCollection" json:"authCollection"`
	AuthRecord     string `db:"authRecord" json:"authRecord"`

	IP   string             `db:"ip" json:"ip"`
	Meta types.JSONMap[any] `db:"meta" json:"meta"`
}

// TableName implements [Model.TableName] interface method.
func (l *LLMLog) TableName() string {
	return LLMLogsTableName
}

// IsCall reports whether the log represents an actual provider call
// (aka. it is not a denied or limited request).
func (l *LLMLog) IsCall() bool {
	return l.Status == LLMLogStatusSuccess || l.Status == LLMLogStatusError
}
