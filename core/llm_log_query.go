package core

import (
	"time"

	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// LLM logs stats intervals.
const (
	LLMLogsStatsIntervalMinute = "minute"
	LLMLogsStatsIntervalHour   = "hour"
	LLMLogsStatsIntervalDay    = "day"
)

// LLM logs stats group by options.
const (
	LLMLogsStatsGroupByProvider = "provider"
	LLMLogsStatsGroupByModel    = "model"
	LLMLogsStatsGroupByProfile  = "profile"
	LLMLogsStatsGroupByUser     = "user"
	LLMLogsStatsGroupByStatus   = "status"
)

// LLM logs top users aggregation options.
const (
	LLMLogsTopUsersByUser = "user"
	LLMLogsTopUsersByIP   = "ip"

	LLMLogsTopUsersSortTokens   = "tokens"
	LLMLogsTopUsersSortRequests = "requests"
)

var llmLogsStatsIntervalFormats = map[string]string{
	LLMLogsStatsIntervalMinute: "%Y-%m-%d %H:%M:00",
	LLMLogsStatsIntervalHour:   "%Y-%m-%d %H:00:00",
	LLMLogsStatsIntervalDay:    "%Y-%m-%d 00:00:00",
}

var llmLogsStatsGroupExprs = map[string]string{
	"":                          "''",
	LLMLogsStatsGroupByProvider: "[[provider]]",
	LLMLogsStatsGroupByModel:    "[[model]]",
	LLMLogsStatsGroupByProfile:  "[[profile]]",
	LLMLogsStatsGroupByStatus:   "[[status]]",
	// note: guests are grouped under an empty string
	LLMLogsStatsGroupByUser: "(CASE WHEN [[authRecord]] != '' THEN [[authCollection]] || '/' || [[authRecord]] ELSE '' END)",
}

// llmCallStatusExpr is an SQL expression that reports whether a log row represents an actual provider call.
const llmCallStatusExpr = "[[status]] IN ('" + LLMLogStatusSuccess + "','" + LLMLogStatusError + "')"

// LLMLogQuery returns a new LLMLog select query.
func (app *BaseApp) LLMLogQuery() *dbx.SelectQuery {
	return app.AuxModelQuery(&LLMLog{})
}

// FindLLMLogById finds a single LLMLog entry by its id.
func (app *BaseApp) FindLLMLogById(id string) (*LLMLog, error) {
	model := &LLMLog{}

	err := app.LLMLogQuery().
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(model)

	if err != nil {
		return nil, err
	}

	return model, nil
}

// DeleteOldLLMLogs deletes all LLM logs created before createdBefore.
//
// For better performance the logs delete is executed as plain SQL statement,
// aka. no delete model hook events will be fired.
func (app *BaseApp) DeleteOldLLMLogs(createdBefore time.Time) error {
	formattedDate := createdBefore.UTC().Format(types.DefaultDateLayout)
	expr := dbx.NewExp("[[created]] <= {:date}", dbx.Params{"date": formattedDate})

	_, err := app.auxNonconcurrentDB.Delete(LLMLogsTableName, expr).Execute()

	return err
}

// -------------------------------------------------------------------

// LLMLogsStatsParams defines the [App.LLMLogsStats] parameters.
type LLMLogsStatsParams struct {
	// Filter is an optional logs filter expression.
	Filter dbx.Expression

	// Interval is the time bucket size - minute, hour (default), day.
	Interval string

	// GroupBy is an optional extra grouping - provider, model, profile, user, status.
	GroupBy string
}

// LLMLogsStatsItem defines a single time bucket (and group) LLM logs statistic.
type LLMLogsStatsItem struct {
	Date types.DateTime `db:"date" json:"date"`

	// Group is the group value (empty if no GroupBy is set;
	// for the "user" grouping it is in the format "collectionId/recordId"
	// and empty for the guests).
	Group string `db:"grp" json:"group"`

	// Requests is the total number of logs (including the denied and limited).
	Requests int `db:"requests" json:"requests"`

	// Errors is the number of failed provider calls.
	Errors int `db:"errors" json:"errors"`

	// Denied is the number of denied or quota limited requests.
	Denied int `db:"denied" json:"denied"`

	InputTokens  int `db:"inputTokens" json:"inputTokens"`
	OutputTokens int `db:"outputTokens" json:"outputTokens"`

	// Latency statistics (only for the actual provider calls).
	AvgDurationMs float64 `db:"avgDurationMs" json:"avgDurationMs"`
	P50DurationMs int     `db:"p50DurationMs" json:"p50DurationMs"`
	P95DurationMs int     `db:"p95DurationMs" json:"p95DurationMs"`
}

// LLMLogsStats returns time bucketed (and optionally grouped) LLM logs statistics
// sorted by date and group in ASC order.
func (app *BaseApp) LLMLogsStats(params LLMLogsStatsParams) ([]*LLMLogsStatsItem, error) {
	format, ok := llmLogsStatsIntervalFormats[params.Interval]
	if !ok {
		format = llmLogsStatsIntervalFormats[LLMLogsStatsIntervalHour]
	}

	groupExpr, ok := llmLogsStatsGroupExprs[params.GroupBy]
	if !ok {
		groupExpr = llmLogsStatsGroupExprs[""]
	}

	inner := app.AuxDB().
		Select(
			"strftime('"+format+"', [[created]]) AS [[date]]",
			groupExpr+" AS [[grp]]",
			"[[status]]",
			"[[inputTokens]]",
			"[[outputTokens]]",
			"[[durationMs]]",
			"(CASE WHEN "+llmCallStatusExpr+" THEN 1 ELSE 0 END) AS [[isCall]]",
		).
		From(LLMLogsTableName)

	if params.Filter != nil {
		inner.AndWhere(params.Filter)
	}

	innerQuery := inner.Build()

	// note: the percentiles are calculated with the "nearest-rank" method
	// using the ROW_NUMBER window function partitioned by the bucket, group and call type
	sql := `
		SELECT
			[[date]],
			[[grp]],
			COUNT(*) AS [[requests]],
			COALESCE(SUM(CASE WHEN [[status]] = '` + LLMLogStatusError + `' THEN 1 ELSE 0 END), 0) AS [[errors]],
			COALESCE(SUM(CASE WHEN [[isCall]] = 0 THEN 1 ELSE 0 END), 0) AS [[denied]],
			COALESCE(SUM([[inputTokens]]), 0) AS [[inputTokens]],
			COALESCE(SUM([[outputTokens]]), 0) AS [[outputTokens]],
			COALESCE(AVG(CASE WHEN [[isCall]] = 1 THEN [[durationMs]] END), 0) AS [[avgDurationMs]],
			COALESCE(MAX(CASE WHEN [[isCall]] = 1 AND [[rn]] = ([[cnt]] * 50 + 99) / 100 THEN [[durationMs]] END), 0) AS [[p50DurationMs]],
			COALESCE(MAX(CASE WHEN [[isCall]] = 1 AND [[rn]] = ([[cnt]] * 95 + 99) / 100 THEN [[durationMs]] END), 0) AS [[p95DurationMs]]
		FROM (
			SELECT
				*,
				ROW_NUMBER() OVER (PARTITION BY [[date]], [[grp]], [[isCall]] ORDER BY [[durationMs]]) AS [[rn]],
				COUNT(*) OVER (PARTITION BY [[date]], [[grp]], [[isCall]]) AS [[cnt]]
			FROM (` + innerQuery.SQL() + `)
		)
		GROUP BY [[date]], [[grp]]
		ORDER BY [[date]] ASC, [[grp]] ASC
	`

	result := []*LLMLogsStatsItem{}

	err := app.AuxDB().NewQuery(sql).Bind(innerQuery.Params()).All(&result)

	return result, err
}

// -------------------------------------------------------------------

// LLMLogsTopUsersParams defines the [App.LLMLogsTopUsers] parameters.
type LLMLogsTopUsersParams struct {
	// Filter is an optional logs filter expression.
	Filter dbx.Expression

	// By specifies the aggregation type:
	//  - "user" (default) - authenticated requests grouped by the auth record
	//  - "ip" - guest requests grouped by the client IP
	By string

	// Sort specifies the result DESC sort - "tokens" (default) or "requests".
	Sort string

	// Limit specifies the max number of returned items (default to 10).
	Limit int
}

// LLMLogsTopUsersItem defines a single LLM logs top users result item.
type LLMLogsTopUsersItem struct {
	AuthCollection string `db:"authCollection" json:"authCollection"`
	AuthRecord     string `db:"authRecord" json:"authRecord"`

	// IP is the guest IP (for the "user" aggregation it is the last used IP).
	IP string `db:"ip" json:"ip"`

	Requests     int `db:"requests" json:"requests"`
	Errors       int `db:"errors" json:"errors"`
	Denied       int `db:"denied" json:"denied"`
	InputTokens  int `db:"inputTokens" json:"inputTokens"`
	OutputTokens int `db:"outputTokens" json:"outputTokens"`
	TotalTokens  int `db:"totalTokens" json:"totalTokens"`

	LastCall types.DateTime `db:"lastCall" json:"lastCall"`
}

// LLMLogsTopUsers returns the LLM logs usage aggregated by user (or guest IP)
// and sorted by the total tokens (or requests) in DESC order.
func (app *BaseApp) LLMLogsTopUsers(params LLMLogsTopUsersParams) ([]*LLMLogsTopUsersItem, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	query := app.LLMLogQuery().
		Select(
			"COUNT(*) AS [[requests]]",
			"COALESCE(SUM(CASE WHEN [[status]] = '"+LLMLogStatusError+"' THEN 1 ELSE 0 END), 0) AS [[errors]]",
			"COALESCE(SUM(CASE WHEN "+llmCallStatusExpr+" THEN 0 ELSE 1 END), 0) AS [[denied]]",
			"COALESCE(SUM([[inputTokens]]), 0) AS [[inputTokens]]",
			"COALESCE(SUM([[outputTokens]]), 0) AS [[outputTokens]]",
			"COALESCE(SUM([[inputTokens]] + [[outputTokens]]), 0) AS [[totalTokens]]",
			"MAX([[created]]) AS [[lastCall]]",
		).
		Limit(int64(limit))

	if params.By == LLMLogsTopUsersByIP {
		query.AndSelect("'' AS [[authCollection]]", "'' AS [[authRecord]]", "[[ip]]").
			AndWhere(dbx.HashExp{"authRecord": ""}).
			GroupBy("ip")
	} else {
		// note: SQLite returns the bare column values from the row with the MAX() aggregate
		query.AndSelect("[[authCollection]]", "[[authRecord]]", "[[ip]]").
			AndWhere(dbx.NewExp("[[authRecord]] != ''")).
			GroupBy("authCollection", "authRecord")
	}

	if params.Sort == LLMLogsTopUsersSortRequests {
		query.OrderBy("requests DESC", "totalTokens DESC")
	} else {
		query.OrderBy("totalTokens DESC", "requests DESC")
	}

	if params.Filter != nil {
		query.AndWhere(params.Filter)
	}

	result := []*LLMLogsTopUsersItem{}

	err := query.All(&result)

	return result, err
}

// -------------------------------------------------------------------

// LLMUsageFilter defines the [App.LLMUsage] filter options.
type LLMUsageFilter struct {
	// Profile is the LLM profile name to check.
	Profile string

	// AuthCollection and AuthRecord are the auth record collection and record ids to match.
	//
	// If AuthRecord is empty, only the guest logs with the specified IP are matched.
	AuthCollection string
	AuthRecord     string

	// IP is the guest IP to match (used only when AuthRecord is empty).
	IP string

	// Since is the start of the usage period.
	Since time.Time
}

func (f LLMUsageFilter) match(l *LLMLog, since types.DateTime) bool {
	if !l.IsCall() || l.Profile != f.Profile || l.Created.Before(since) {
		return false
	}

	if f.AuthRecord != "" {
		return l.AuthCollection == f.AuthCollection && l.AuthRecord == f.AuthRecord
	}

	return l.AuthRecord == "" && l.IP == f.IP
}

// LLMUsage defines the aggregated LLM usage for a specific period.
type LLMUsage struct {
	Requests     int `db:"requests" json:"requests"`
	InputTokens  int `db:"inputTokens" json:"inputTokens"`
	OutputTokens int `db:"outputTokens" json:"outputTokens"`

	// Oldest is the created date of the oldest counted log (zero if none).
	Oldest types.DateTime `db:"oldest" json:"oldest"`
}

// TotalTokens returns the sum of the input and output tokens.
func (u *LLMUsage) TotalTokens() int {
	return u.InputTokens + u.OutputTokens
}

// LLMUsage returns the LLM usage (requests and tokens) of the actual provider
// calls (aka. excluding the denied and limited requests) matching the specified filter.
//
// The result includes also the queued but not yet persisted logs.
func (app *BaseApp) LLMUsage(filter LLMUsageFilter) (*LLMUsage, error) {
	since, err := types.ParseDateTime(filter.Since)
	if err != nil {
		return nil, err
	}

	// the queued logs that are not persisted yet
	var queued []*LLMLog
	for _, l := range app.llmLogsWriter.snapshot() {
		if filter.match(l, since) {
			queued = append(queued, l)
		}
	}

	query := app.LLMLogQuery().
		Select(
			"COUNT(*) AS [[requests]]",
			"COALESCE(SUM([[inputTokens]]), 0) AS [[inputTokens]]",
			"COALESCE(SUM([[outputTokens]]), 0) AS [[outputTokens]]",
			"COALESCE(MIN([[created]]), '') AS [[oldest]]",
		).
		AndWhere(dbx.HashExp{"profile": filter.Profile}).
		AndWhere(dbx.NewExp(llmCallStatusExpr)).
		AndWhere(dbx.NewExp("[[created]] >= {:since}", dbx.Params{"since": since.String()}))

	if filter.AuthRecord != "" {
		query.AndWhere(dbx.HashExp{
			"authCollection": filter.AuthCollection,
			"authRecord":     filter.AuthRecord,
		})
	} else {
		query.AndWhere(dbx.HashExp{
			"authRecord": "",
			"ip":         filter.IP,
		})
	}

	// exclude the queued logs that could have been persisted in the meantime
	if len(queued) > 0 {
		ids := make([]any, len(queued))
		for i, l := range queued {
			ids[i] = l.Id
		}
		query.AndWhere(dbx.NotIn("id", ids...))
	}

	usage := &LLMUsage{}

	err = query.One(usage)
	if err != nil {
		return nil, err
	}

	for _, l := range queued {
		usage.Requests++
		usage.InputTokens += l.InputTokens
		usage.OutputTokens += l.OutputTokens
		if usage.Oldest.IsZero() || l.Created.Before(usage.Oldest) {
			usage.Oldest = l.Created
		}
	}

	return usage, nil
}
