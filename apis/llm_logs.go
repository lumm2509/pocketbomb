package apis

import (
	"net/http"
	"strconv"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

var llmLogFilterFields = []string{
	"id", "created", "provider", "model", "profile", "stream", "status", "error",
	"inputTokens", "outputTokens", "durationMs", "authCollection", "authRecord", "ip", "meta",
	`^meta\.[\w\.\:]*\w+$`,
}

func llmLogsList(e *core.RequestEvent) error {
	fieldResolver := search.NewSimpleFieldResolver(llmLogFilterFields...)

	result, err := search.NewProvider(fieldResolver).
		Query(e.App.LLMLogQuery()).
		ParseAndExec(e.Request.URL.Query().Encode(), &[]*core.LLMLog{})

	if err != nil {
		return e.BadRequestError("", err)
	}

	return e.JSON(http.StatusOK, result)
}

func llmLogsTruncate(e *core.RequestEvent) error {
	// delete all rows directly (aka. no model hooks will be fired)
	_, err := e.App.AuxNonconcurrentDB().Delete(core.LLMLogsTableName, nil).Execute()
	if err != nil {
		return e.InternalServerError("Failed to truncate all LLM logs.", err)
	}

	// try to free the unused disk space
	err = e.App.AuxVacuum()
	if err != nil {
		e.App.Logger().Warn("Failed to VACUUM aux database", "error", err)
	}

	return e.NoContent(http.StatusNoContent)
}

func llmLogsView(e *core.RequestEvent) error {
	id := e.Request.PathValue("id")
	if id == "" {
		return e.NotFoundError("", nil)
	}

	log, err := e.App.FindLLMLogById(id)
	if err != nil || log == nil {
		return e.NotFoundError("", err)
	}

	return e.JSON(http.StatusOK, log)
}

// parseLLMLogsFilter parses the optional "filter" query parameter.
func parseLLMLogsFilter(e *core.RequestEvent) (dbx.Expression, error) {
	filter := e.Request.URL.Query().Get(search.FilterQueryParam)
	if filter == "" {
		return nil, nil
	}

	return search.FilterData(filter).BuildExpr(search.NewSimpleFieldResolver(llmLogFilterFields...))
}

func llmLogsStats(e *core.RequestEvent) error {
	query := e.Request.URL.Query()

	params := core.LLMLogsStatsParams{
		Interval: query.Get("interval"),
		GroupBy:  query.Get("groupBy"),
	}

	err := validation.Errors{
		"interval": validation.Validate(params.Interval, validation.In(
			core.LLMLogsStatsIntervalMinute,
			core.LLMLogsStatsIntervalHour,
			core.LLMLogsStatsIntervalDay,
		)),
		"groupBy": validation.Validate(params.GroupBy, validation.In(
			core.LLMLogsStatsGroupByProvider,
			core.LLMLogsStatsGroupByModel,
			core.LLMLogsStatsGroupByProfile,
			core.LLMLogsStatsGroupByUser,
			core.LLMLogsStatsGroupByStatus,
		)),
	}.Filter()
	if err != nil {
		return e.BadRequestError("Invalid stats parameters.", err)
	}

	params.Filter, err = parseLLMLogsFilter(e)
	if err != nil {
		return e.BadRequestError("Invalid filter format.", err)
	}

	stats, err := e.App.LLMLogsStats(params)
	if err != nil {
		return e.BadRequestError("Failed to generate LLM logs stats.", err)
	}

	return e.JSON(http.StatusOK, stats)
}

// llmLogsTopUsersItem extends the core top users item with the related auth record (if any).
type llmLogsTopUsersItem struct {
	*core.LLMLogsTopUsersItem

	// Record is the related auth record (nil for guests or deleted records).
	Record *core.Record `json:"record"`
}

func llmLogsTopUsers(e *core.RequestEvent) error {
	query := e.Request.URL.Query()

	params := core.LLMLogsTopUsersParams{
		By:   query.Get("by"),
		Sort: query.Get("sort"),
	}

	limitStr := query.Get("limit")
	if limitStr != "" {
		params.Limit, _ = strconv.Atoi(limitStr)
	} else {
		params.Limit = 10
	}

	err := validation.Errors{
		"by":    validation.Validate(params.By, validation.In(core.LLMLogsTopUsersByUser, core.LLMLogsTopUsersByIP)),
		"sort":  validation.Validate(params.Sort, validation.In(core.LLMLogsTopUsersSortTokens, core.LLMLogsTopUsersSortRequests)),
		"limit": validation.Validate(params.Limit, validation.Required, validation.Min(1), validation.Max(100)),
	}.Filter()
	if err != nil {
		return e.BadRequestError("Invalid top users parameters.", err)
	}

	params.Filter, err = parseLLMLogsFilter(e)
	if err != nil {
		return e.BadRequestError("Invalid filter format.", err)
	}

	items, err := e.App.LLMLogsTopUsers(params)
	if err != nil {
		return e.BadRequestError("Failed to generate LLM logs top users.", err)
	}

	// load the related auth records
	idsByCollection := map[string][]string{}
	for _, item := range items {
		if item.AuthRecord != "" {
			idsByCollection[item.AuthCollection] = append(idsByCollection[item.AuthCollection], item.AuthRecord)
		}
	}

	records := map[string]*core.Record{}
	for collectionId, ids := range idsByCollection {
		found, err := e.App.FindRecordsByIds(collectionId, ids)
		if err != nil {
			continue // missing collection
		}
		for _, r := range found {
			r.IgnoreEmailVisibility(true)
			records[collectionId+"/"+r.Id] = r
		}
	}

	result := make([]*llmLogsTopUsersItem, len(items))
	for i, item := range items {
		result[i] = &llmLogsTopUsersItem{
			LLMLogsTopUsersItem: item,
			Record:              records[item.AuthCollection+"/"+item.AuthRecord],
		}
	}

	return e.JSON(http.StatusOK, result)
}
