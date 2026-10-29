package core

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/search"
)

// requestRuleBaseName is the name of the in-memory placeholder collection
// used as base of the "@request.*"-only rules resolver.
const requestRuleBaseName = "__pbRequestRule__"

// newRequestRuleResolver creates a new field resolver for access rules
// that are not bound to a specific collection record
// (aka. only "@request.*" and "@collection.*" fields are allowed).
func newRequestRuleResolver(app App, requestInfo *RequestInfo) *RecordFieldResolver {
	r := NewRecordFieldResolver(app, NewBaseCollection(requestRuleBaseName), requestInfo, true)

	// allow only the "@request.*" and "@collection.*" fields
	allowed := r.AllowedFields()
	filtered := make([]string, 0, len(allowed))
	for _, pattern := range allowed {
		if strings.HasPrefix(pattern, `^\@`) {
			filtered = append(filtered, pattern)
		}
	}
	r.SetAllowedFields(filtered)

	return r
}

// CanAccessRequestRule checks whether the provided requestInfo satisfies
// an access rule that is not bound to a specific collection record
// (e.g. the LLM profiles rule).
//
// It has the same semantics as the collection API rules:
//   - Owners can always access
//   - nil rule: only Owners can access
//   - empty rule: everyone can access
//   - non-empty rule: the "@request.*" (and "@collection.*") filter expression must be satisfied
func CanAccessRequestRule(app App, requestInfo *RequestInfo, rule *string) (bool, error) {
	if requestInfo == nil {
		requestInfo = &RequestInfo{}
	}

	// Owners can access everything
	if requestInfo.IsOwner(app) {
		return true, nil
	}

	// only Owners can access
	if rule == nil {
		return false, nil
	}

	// empty public rule, aka. everyone can access
	if *rule == "" {
		return true, nil
	}

	resolver := newRequestRuleResolver(app, requestInfo)

	expr, err := search.FilterData(*rule).BuildExpr(resolver)
	if err != nil {
		return false, err
	}

	// note: the single row subquery is used as base "table" so that
	// the resolver could still register joins (e.g. for "@collection.*")
	query := app.ConcurrentDB().
		Select("(1)").
		From("(SELECT 1) " + requestRuleBaseName)

	err = resolver.UpdateQuery(query)
	if err != nil {
		return false, err
	}

	var exists int

	err = query.AndWhere(expr).Limit(1).Row(&exists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	return exists > 0, nil
}

// validateRequestRule checks whether the rule is a valid "@request.*"-only filter expression.
func validateRequestRule(app App, rule *string) error {
	if rule == nil || *rule == "" {
		return nil
	}

	_, err := search.FilterData(*rule).BuildExpr(newRequestRuleResolver(app, &RequestInfo{}))

	return err
}
