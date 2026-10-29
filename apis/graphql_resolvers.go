package apis

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	"github.com/spf13/cast"
)

const (
	graphqlDefaultPageSize = 50

	// graphqlRelationsChunkSize is the max number of related record ids loaded with a single query
	graphqlRelationsChunkSize = 500
)

type graphqlRequestKey struct{}

// graphqlRequest is the per request GraphQL execution state.
type graphqlRequest struct {
	event  *core.RequestEvent
	info   *core.RequestInfo
	ctx    context.Context
	schema *graphqlSchema

	// loaders are the relation loaders per related collection id
	// (note: the executor resolves the fields in a single goroutine)
	loaders map[string]*graphqlRelationLoader
}

func graphqlRequestFrom(ctx context.Context) *graphqlRequest {
	req, _ := ctx.Value(graphqlRequestKey{}).(*graphqlRequest)
	return req
}

// graphqlRecord is the source value of the collection object types.
type graphqlRecord struct {
	record *core.Record

	// export is the enriched record public export (aka. the REST API record JSON)
	export map[string]any
}

func newGraphQLRecords(records []*core.Record) []*graphqlRecord {
	result := make([]*graphqlRecord, len(records))
	for i, r := range records {
		result[i] = &graphqlRecord{record: r, export: r.PublicExport()}
	}
	return result
}

// -------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------

// graphqlError is a GraphQL error with a public safe message and the REST API error status and data as extensions.
type graphqlError struct {
	message    string
	extensions map[string]any
}

func (e *graphqlError) Error() string {
	return e.message
}

func (e *graphqlError) Extensions() map[string]any {
	return e.extensions
}

func newGraphQLError(message string) *graphqlError {
	return &graphqlError{message: message, extensions: map[string]any{"status": 400}}
}

// toGraphQLError converts the records read path errors into GraphQL errors
// with the same public message and data as the REST API errors (never the internal error details).
func toGraphQLError(err error) error {
	var gqlErr *graphqlError
	if errors.As(err, &gqlErr) {
		return gqlErr
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &graphqlError{message: "The request timed out.", extensions: map[string]any{"status": 408}}
	}

	apiErr := firstApiError(err, router.NewBadRequestError("", err))

	return &graphqlError{
		message:    apiErr.Message,
		extensions: map[string]any{"status": apiErr.Status, "data": apiErr.Data},
	}
}

// -------------------------------------------------------------------
// Record fields
// -------------------------------------------------------------------

func graphqlValueResolver(name string, convert func(v any) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		r, _ := p.Source.(*graphqlRecord)
		if r == nil {
			return nil, nil
		}

		v, ok := r.export[name]
		if !ok || v == nil {
			return nil, nil
		}

		if point, ok := v.(types.GeoPoint); ok {
			return map[string]any{"lon": point.Lon, "lat": point.Lat}, nil
		}

		return convert(v), nil
	}
}

// graphqlFile is the source value of the File type.
type graphqlFile struct {
	record    *core.Record
	filename  string
	protected bool
}

func resolveRecordFiles(name string, multiple bool, protected bool) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		r, _ := p.Source.(*graphqlRecord)
		if r == nil {
			return nil, nil
		}

		v, ok := r.export[name]
		if !ok {
			return nil, nil
		}

		names := list.ToUniqueStringSlice(v)

		files := make([]*graphqlFile, 0, len(names))
		for _, n := range names {
			if n != "" {
				files = append(files, &graphqlFile{record: r.record, filename: n, protected: protected})
			}
		}

		if multiple {
			return files, nil
		}

		if len(files) == 0 {
			return nil, nil
		}

		return files[0], nil
	}
}

func resolveFileName(p graphql.ResolveParams) (any, error) {
	f, _ := p.Source.(*graphqlFile)
	if f == nil {
		return nil, nil
	}

	return f.filename, nil
}

// resolveFileURL returns the absolute file URL
// (for the protected files only with the provided file token, aka. the existing file token mechanism).
func resolveFileURL(p graphql.ResolveParams) (any, error) {
	f, _ := p.Source.(*graphqlFile)
	req := graphqlRequestFrom(p.Context)
	if f == nil || req == nil {
		return nil, nil
	}

	token, _ := p.Args["token"].(string)
	if f.protected && token == "" {
		return nil, nil
	}

	result := strings.TrimRight(req.event.App.Settings().Meta.AppURL, "/") +
		"/api/files/" + url.PathEscape(f.record.Collection().Id) +
		"/" + url.PathEscape(f.record.Id) +
		"/" + url.PathEscape(f.filename)

	if f.protected {
		result += "?token=" + url.QueryEscape(token)
	}

	return result, nil
}

func resolveRecordRelation(name string, target *core.Collection, multiple bool) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		r, _ := p.Source.(*graphqlRecord)
		req := graphqlRequestFrom(p.Context)
		if r == nil || req == nil {
			return nil, nil
		}

		ids := slices.DeleteFunc(list.ToUniqueStringSlice(r.export[name]), func(id string) bool {
			return id == ""
		})

		loader := req.loader(target)
		loader.add(ids...)

		// deferred so that the ids of the same depth level are loaded together
		return func() (any, error) {
			if err := loader.load(req); err != nil {
				return nil, err
			}

			if multiple {
				result := make([]*graphqlRecord, 0, len(ids))
				for _, id := range ids {
					if rel := loader.records[id]; rel != nil {
						result = append(result, rel)
					}
				}
				return result, nil
			}

			if len(ids) == 0 || loader.records[ids[0]] == nil {
				return nil, nil
			}

			return loader.records[ids[0]], nil
		}, nil
	}
}

// graphqlRelationLoader batches the related records loading of a single collection
// through the records expand path (Authorize, ViewRule, OnRecordEnrich hooks and visibility flags).
type graphqlRelationLoader struct {
	collection *core.Collection
	pending    []string
	requested  map[string]struct{}
	records    map[string]*graphqlRecord
}

func (req *graphqlRequest) loader(collection *core.Collection) *graphqlRelationLoader {
	l := req.loaders[collection.Id]
	if l == nil {
		l = &graphqlRelationLoader{
			collection: collection,
			requested:  map[string]struct{}{},
			records:    map[string]*graphqlRecord{},
		}
		req.loaders[collection.Id] = l
	}

	return l
}

func (l *graphqlRelationLoader) add(ids ...string) {
	for _, id := range ids {
		if _, ok := l.requested[id]; ok {
			continue
		}
		l.requested[id] = struct{}{}
		l.pending = append(l.pending, id)
	}
}

func (l *graphqlRelationLoader) load(req *graphqlRequest) error {
	if len(l.pending) == 0 {
		return nil
	}

	pending := l.pending
	l.pending = nil

	fetch := expandFetch(req.event.App, req.info)

	for chunk := range slices.Chunk(pending, graphqlRelationsChunkSize) {
		if err := req.ctx.Err(); err != nil {
			return toGraphQLError(err)
		}

		records, err := fetch(l.collection, chunk)
		if err != nil {
			// similar to the REST API expand the inaccessible relations are omitted
			req.event.App.Logger().Debug("GraphQL: failed to load relations", "collection", l.collection.Name, "error", err)
			continue
		}

		for _, rel := range newGraphQLRecords(records) {
			l.records[rel.record.Id] = rel
		}
	}

	return nil
}

// -------------------------------------------------------------------
// Root query fields
// -------------------------------------------------------------------

func (s *graphqlSchema) resolveNode(p graphql.ResolveParams) (any, error) {
	req := graphqlRequestFrom(p.Context)
	globalId, _ := p.Args["id"].(string)

	collectionName, recordId, err := parseGraphQLGlobalId(globalId)
	if err != nil || req == nil {
		return nil, nil
	}

	t := s.types[collectionName]
	if t == nil {
		return nil, nil
	}

	return req.viewRecord(t.collection, dbx.HashExp{t.collection.Name + ".id": recordId})
}

func (s *graphqlSchema) singularQueryField(t *graphqlCollectionType) *graphql.Field {
	args := graphql.FieldConfigArgument{
		"id": &graphql.ArgumentConfig{Type: graphql.ID, Description: "The record global ID."},
	}
	argNames := []string{"id"}
	for argName := range t.uniqueArgs {
		args[argName] = &graphql.ArgumentConfig{Type: graphql.String}
		argNames = append(argNames, argName)
	}
	slices.Sort(argNames[1:])

	return &graphql.Field{
		Type:        t.object,
		Description: "Fetches a single " + t.collection.Name + " record (the View API rule applies).",
		Args:        args,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			req := graphqlRequestFrom(p.Context)
			if req == nil {
				return nil, nil
			}

			var argName string
			var total int
			for k, v := range p.Args {
				if v != nil {
					argName = k
					total++
				}
			}
			if total != 1 {
				return nil, newGraphQLError("Exactly one of the arguments " + strings.Join(argNames, ", ") + " must be provided.")
			}

			value, _ := p.Args[argName].(string)

			if argName == "id" {
				collectionName, recordId, err := parseGraphQLGlobalId(value)
				if err != nil || collectionName != t.collection.Name {
					return req.viewRecord(t.collection, nil)
				}

				return req.viewRecord(t.collection, dbx.HashExp{t.collection.Name + ".id": recordId})
			}

			return req.viewRecord(t.collection, dbx.HashExp{t.collection.Name + "." + t.uniqueArgs[argName]: value})
		},
	}
}

// viewRecord fetches a single record through the records view API path
// (nil if it is missing or not visible; an error if the actor is not allowed to view the collection records).
//
// A nil where expression (e.g. an invalid id) is a missing record.
func (req *graphqlRequest) viewRecord(collection *core.Collection, where dbx.Expression) (any, error) {
	if err := req.ctx.Err(); err != nil {
		return nil, toGraphQLError(err)
	}

	ruleFunc, err := recordViewRuleFunc(req.event, req.info, collection)
	if err != nil {
		return nil, toGraphQLError(err)
	}

	if where == nil {
		return nil, nil
	}

	query := req.event.App.RecordQuery(collection).WithContext(req.ctx).AndWhere(where)
	if err := ruleFunc(query); err != nil {
		return nil, nil
	}

	record := &core.Record{}
	if err := query.Limit(1).One(record); err != nil {
		if errors.Is(err, sql.ErrNoRows) || req.ctx.Err() == nil {
			return nil, nil
		}
		return nil, toGraphQLError(err)
	}

	if err := enrichRecords(req.event.App, req.info, []*core.Record{record}); err != nil {
		return nil, toGraphQLError(firstApiError(err, router.NewInternalServerError("Failed to enrich record", err)))
	}

	return newGraphQLRecords([]*core.Record{record})[0], nil
}

func (s *graphqlSchema) pluralQueryField(t *graphqlCollectionType) *graphql.Field {
	return &graphql.Field{
		Type:        t.connection,
		Description: "Lists the " + t.collection.Name + " records (the List API rule applies; null with an error if not allowed).",
		Args: graphql.FieldConfigArgument{
			"first":   &graphql.ArgumentConfig{Type: graphql.Int},
			"after":   &graphql.ArgumentConfig{Type: graphql.String},
			"last":    &graphql.ArgumentConfig{Type: graphql.Int},
			"before":  &graphql.ArgumentConfig{Type: graphql.String},
			"filter":  &graphql.ArgumentConfig{Type: graphql.String, Description: "PocketBase filter expression."},
			"sort":    &graphql.ArgumentConfig{Type: graphql.String, Description: "PocketBase sort expression (only the collection scalar fields)."},
			"reverse": &graphql.ArgumentConfig{Type: graphql.Boolean},
		},
		Resolve: func(p graphql.ResolveParams) (any, error) {
			req := graphqlRequestFrom(p.Context)
			if req == nil {
				return nil, nil
			}

			conn, err := req.newConnection(t, p.Args)
			if err != nil {
				return nil, toGraphQLError(err)
			}

			return conn, nil
		},
	}
}

// -------------------------------------------------------------------
// Connections (keyset pagination)
// -------------------------------------------------------------------

type graphqlSortKey struct {
	field core.Field
	desc  bool
}

// graphqlCursor is the decoded opaque connection cursor.
type graphqlCursor struct {
	// Hash is the hash of the collection and the effective sort
	Hash string `json:"h"`

	// Values are the sort key values of the record (incl. the id)
	Values []any `json:"v"`
}

type graphqlConnection struct {
	req *graphqlRequest
	t   *graphqlCollectionType

	filter   string
	sort     string
	keys     []graphqlSortKey // the effective order (incl. the id tiebreaker)
	hash     string
	backward bool
	cursor   *graphqlCursor // the "after" cursor of the forward and the "before" cursor of the backward pagination

	records []*graphqlRecord
	hasMore bool

	cursors    map[string]string
	cursorsErr error
	totalCount *int
	hasOther   *bool
}

func (req *graphqlRequest) newConnection(t *graphqlCollectionType, args map[string]any) (*graphqlConnection, error) {
	first, hasFirst := args["first"].(int)
	last, hasLast := args["last"].(int)
	after, _ := args["after"].(string)
	before, _ := args["before"].(string)
	reverse, _ := args["reverse"].(bool)

	maxPageSize := req.event.App.Settings().GraphQL.MaxPageSize

	if hasFirst && hasLast {
		return nil, newGraphQLError("Passing both first and last is not supported.")
	}
	if (hasFirst || after != "") && before != "" || (hasLast || before != "") && after != "" {
		return nil, newGraphQLError("Use either first/after (forward) or last/before (backward) pagination.")
	}

	limit := graphqlDefaultPageSize
	if hasFirst {
		limit = first
	} else if hasLast {
		limit = last
	}
	if limit < 0 || limit > maxPageSize {
		return nil, newGraphQLError(fmt.Sprintf("The first and last arguments must be between 0 and %d.", maxPageSize))
	}

	conn := &graphqlConnection{
		req:      req,
		t:        t,
		filter:   stringArg(args, "filter"),
		sort:     stringArg(args, "sort"),
		backward: hasLast || before != "",
	}

	keys, err := graphqlSortKeys(t, conn.sort, reverse)
	if err != nil {
		return nil, err
	}
	conn.keys = keys
	conn.hash = graphqlSortHash(t.collection, keys)

	rawCursor := after
	if conn.backward {
		rawCursor = before
	}
	if rawCursor != "" {
		conn.cursor, err = decodeGraphQLCursor(rawCursor, conn.hash, len(keys))
		if err != nil {
			return nil, err
		}
	}

	records, err := conn.fetch(conn.fetchKeys(), conn.cursor, limit+1, true)
	if err != nil {
		return nil, err
	}

	if len(records) > limit {
		conn.hasMore = true
		records = records[:limit]
	}

	if conn.backward {
		slices.Reverse(records)
	}

	if err := enrichRecords(req.event.App, req.info, records); err != nil {
		return nil, firstApiError(err, router.NewInternalServerError("Failed to enrich records", err))
	}

	conn.records = newGraphQLRecords(records)

	return conn, nil
}

func stringArg(args map[string]any, name string) string {
	v, _ := args[name].(string)
	return v
}

// fetchKeys returns the database order of the current page (reversed for the backward pagination).
func (c *graphqlConnection) fetchKeys() []graphqlSortKey {
	if c.backward {
		return flipGraphQLSortKeys(c.keys)
	}
	return c.keys
}

// fetch loads the records after the cursor in the provided order through the records list API path.
func (c *graphqlConnection) fetch(keys []graphqlSortKey, cursor *graphqlCursor, limit int, isPage bool) ([]*core.Record, error) {
	if err := c.req.ctx.Err(); err != nil {
		return nil, err
	}

	collection := c.t.collection

	query := c.req.event.App.RecordQuery(collection).WithContext(c.req.ctx)

	if cursor != nil {
		query.AndWhere(graphqlKeysetExpr(collection.Name, keys, cursor.Values))
	}

	for _, k := range keys {
		dir := search.SortAsc
		if k.desc {
			dir = search.SortDesc
		}
		query.AndOrderBy("[[" + collection.Name + "." + k.field.GetName() + "]] " + dir)
	}

	provider, access, err := recordsListProvider(c.req.event, c.req.info, collection, query, c.filter, c.sort)
	if err != nil {
		return nil, err
	}

	if c.filter != "" {
		provider.AddFilter(search.FilterData(c.filter))
	}

	records := []*core.Record{}

	_, err = provider.SkipTotal(true).PerPage(limit).Exec(&records)
	if err != nil {
		return nil, firstApiError(err, router.NewBadRequestError("", err))
	}

	if isPage {
		throttleEmptyFilteredList(c.req.event, collection, access.BypassRules, c.filter, len(records))
	}

	return records, nil
}

// hasOtherPage reports whether there are records before the "after" cursor (forward)
// or after the "before" cursor (backward).
func (c *graphqlConnection) hasOtherPage() (bool, error) {
	if c.hasOther != nil {
		return *c.hasOther, nil
	}

	var result bool
	if c.cursor != nil {
		records, err := c.fetch(flipGraphQLSortKeys(c.fetchKeys()), c.cursor, 1, false)
		if err != nil {
			return false, err
		}
		result = len(records) > 0
	}
	c.hasOther = &result

	return result, nil
}

func (c *graphqlConnection) count() (int, error) {
	if c.totalCount != nil {
		return *c.totalCount, nil
	}

	query := c.req.event.App.RecordQuery(c.t.collection).WithContext(c.req.ctx)

	provider, _, err := recordsListProvider(c.req.event, c.req.info, c.t.collection, query, c.filter, c.sort)
	if err != nil {
		return 0, err
	}

	if c.filter != "" {
		provider.AddFilter(search.FilterData(c.filter))
	}

	result, err := provider.PerPage(1).Exec(&[]*core.Record{})
	if err != nil {
		return 0, firstApiError(err, router.NewBadRequestError("", err))
	}
	c.totalCount = &result.TotalItems

	return result.TotalItems, nil
}

// cursorFor returns the cursor of a page record.
//
// The sort key values are loaded with a single query for all page records
// so that the NULL values (e.g. view collections) are preserved.
func (c *graphqlConnection) cursorFor(r *graphqlRecord) (string, error) {
	if c.cursors == nil && c.cursorsErr == nil {
		c.cursors, c.cursorsErr = c.loadCursors()
	}

	if c.cursorsErr != nil {
		return "", c.cursorsErr
	}

	return c.cursors[r.record.Id], nil
}

func (c *graphqlConnection) loadCursors() (map[string]string, error) {
	result := make(map[string]string, len(c.records))
	if len(c.records) == 0 {
		return result, nil
	}

	columns := make([]string, 0, len(c.keys)+1)
	columns = append(columns, "[[id]]")
	for i, k := range c.keys {
		columns = append(columns, "[["+k.field.GetName()+"]] AS [[k"+strconv.Itoa(i)+"]]")
	}

	ids := make([]any, len(c.records))
	for i, r := range c.records {
		ids[i] = r.record.Id
	}

	rows := []dbx.NullStringMap{}
	err := c.req.event.App.ConcurrentDB().Select(columns...).
		From(c.t.collection.Name).
		AndWhere(dbx.In("id", ids...)).
		WithContext(c.req.ctx).
		All(&rows)
	if err != nil {
		return nil, err
	}

	rowsById := make(map[string]dbx.NullStringMap, len(rows))
	for _, row := range rows {
		rowsById[row["id"].String] = row
	}

	for _, r := range c.records {
		row := rowsById[r.record.Id]

		values := make([]any, len(c.keys))
		for i, k := range c.keys {
			name := k.field.GetName()

			// the cursor must not reveal a value that is not visible in the record itself
			// (e.g. an auth record email without emailVisibility or a field hidden by an OnRecordEnrich hook)
			if _, ok := r.export[name]; !ok && name != core.FieldNameId {
				return nil, newGraphQLError(fmt.Sprintf("Cursors are not available when sorting by the not visible field %q.", name))
			}

			raw := row["k"+strconv.Itoa(i)]
			if !raw.Valid {
				continue // NULL
			}

			// note: typed values for the columns that could be without type affinity (e.g. view expressions)
			switch k.field.(type) {
			case *core.NumberField:
				values[i] = cast.ToFloat64(raw.String)
			case *core.BoolField:
				values[i] = cast.ToBool(raw.String)
			default:
				values[i] = raw.String
			}
		}

		encoded, err := json.Marshal(graphqlCursor{Hash: c.hash, Values: values})
		if err != nil {
			return nil, err
		}

		result[r.record.Id] = base64.RawURLEncoding.EncodeToString(encoded)
	}

	return result, nil
}

// graphqlSortKeys returns the connection order of the client sort expression
// (only the collection sortable fields; the id is always the last key).
//
// The default order is "created" (if the collection has such field) and the id.
func graphqlSortKeys(t *graphqlCollectionType, rawSort string, reverse bool) ([]graphqlSortKey, error) {
	keys := []graphqlSortKey{}

	if strings.TrimSpace(rawSort) == "" {
		if f, ok := t.sortable["created"]; ok {
			keys = append(keys, graphqlSortKey{field: f})
		}
	} else {
		sortFields := search.ParseSortFromString(rawSort)
		if len(sortFields) > search.DefaultSortExprLimit {
			return nil, newGraphQLError("Too many sort fields.")
		}

		for _, sf := range sortFields {
			f, ok := t.sortable[sf.Name]
			if !ok {
				return nil, newGraphQLError(fmt.Sprintf("Invalid sort field %q (only the collection scalar fields are allowed).", sf.Name))
			}

			if slices.ContainsFunc(keys, func(k graphqlSortKey) bool { return k.field.GetName() == sf.Name }) {
				continue
			}

			keys = append(keys, graphqlSortKey{field: f, desc: sf.Direction == search.SortDesc})
		}
	}

	if !slices.ContainsFunc(keys, func(k graphqlSortKey) bool { return k.field.GetName() == core.FieldNameId }) {
		keys = append(keys, graphqlSortKey{field: t.sortable[core.FieldNameId]})
	}

	if reverse {
		keys = flipGraphQLSortKeys(keys)
	}

	return keys, nil
}

func flipGraphQLSortKeys(keys []graphqlSortKey) []graphqlSortKey {
	result := make([]graphqlSortKey, len(keys))
	for i, k := range keys {
		result[i] = graphqlSortKey{field: k.field, desc: !k.desc}
	}
	return result
}

func graphqlSortHash(collection *core.Collection, keys []graphqlSortKey) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		dir := search.SortAsc
		if k.desc {
			dir = search.SortDesc
		}
		parts[i] = k.field.GetName() + " " + dir
	}

	sum := sha256.Sum256([]byte(collection.Id + "|" + strings.Join(parts, ",")))

	return hex.EncodeToString(sum[:8])
}

func decodeGraphQLCursor(raw string, hash string, totalKeys int) (*graphqlCursor, error) {
	invalidErr := newGraphQLError("Invalid cursor (it must be from the same collection and sort).")

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, invalidErr
	}

	cursor := &graphqlCursor{}
	if err := json.Unmarshal(decoded, cursor); err != nil || cursor.Hash != hash || len(cursor.Values) != totalKeys {
		return nil, invalidErr
	}

	for _, v := range cursor.Values {
		switch v.(type) {
		case nil, string, float64, bool:
		default:
			return nil, invalidErr
		}
	}

	return cursor, nil
}

// graphqlKeysetExpr returns the expression of the rows after the provided sort key values in the keys order:
//
//	(k1 > v1) OR (k1 = v1 AND k2 > v2) OR ...
//
// The NULL values are ordered as in SQLite (smaller than any other value).
func graphqlKeysetExpr(tableName string, keys []graphqlSortKey, values []any) dbx.Expression {
	ors := make([]dbx.Expression, 0, len(keys))

	for i, k := range keys {
		ands := make([]dbx.Expression, 0, i+1)

		for j := 0; j < i; j++ {
			ands = append(ands, graphqlKeyCompareExpr(tableName, keys[j], values[j], j, true))
		}
		ands = append(ands, graphqlKeyCompareExpr(tableName, k, values[i], i, false))

		ors = append(ors, dbx.And(ands...))
	}

	return dbx.Enclose(dbx.Or(ors...))
}

func graphqlKeyCompareExpr(tableName string, k graphqlSortKey, value any, index int, equal bool) dbx.Expression {
	col := "[[" + tableName + "." + k.field.GetName() + "]]"
	param := "pbCursor" + strconv.Itoa(index)

	if equal {
		if value == nil {
			return dbx.NewExp(col + " IS NULL")
		}
		return dbx.NewExp(col+" = {:"+param+"}", dbx.Params{param: value})
	}

	if value == nil {
		if k.desc {
			return dbx.NewExp("0 = 1") // nothing is after NULL in descending order
		}
		return dbx.NewExp(col + " IS NOT NULL")
	}

	if k.desc {
		return dbx.NewExp("("+col+" < {:"+param+"} OR "+col+" IS NULL)", dbx.Params{param: value})
	}

	return dbx.NewExp(col+" > {:"+param+"}", dbx.Params{param: value})
}

// -------------------------------------------------------------------
// Connection fields
// -------------------------------------------------------------------

type graphqlEdge struct {
	conn   *graphqlConnection
	record *graphqlRecord
}

func resolveConnectionEdges(p graphql.ResolveParams) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil {
		return nil, nil
	}

	edges := make([]*graphqlEdge, len(c.records))
	for i, r := range c.records {
		edges[i] = &graphqlEdge{conn: c, record: r}
	}

	return edges, nil
}

func resolveConnectionNodes(p graphql.ResolveParams) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil {
		return nil, nil
	}

	return c.records, nil
}

func resolveConnectionPageInfo(p graphql.ResolveParams) (any, error) {
	return p.Source, nil
}

func resolveConnectionTotalCount(p graphql.ResolveParams) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil {
		return nil, nil
	}

	total, err := c.count()
	if err != nil {
		return nil, toGraphQLError(err)
	}

	return total, nil
}

func resolveEdgeCursor(p graphql.ResolveParams) (any, error) {
	e, _ := p.Source.(*graphqlEdge)
	if e == nil {
		return nil, nil
	}

	cursor, err := e.conn.cursorFor(e.record)
	if err != nil {
		return nil, toGraphQLError(err)
	}

	return cursor, nil
}

func resolveEdgeNode(p graphql.ResolveParams) (any, error) {
	e, _ := p.Source.(*graphqlEdge)
	if e == nil {
		return nil, nil
	}

	return e.record, nil
}

func resolvePageInfoHasNext(p graphql.ResolveParams) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil {
		return false, nil
	}

	if !c.backward {
		return c.hasMore, nil
	}

	result, err := c.hasOtherPage()
	if err != nil {
		return nil, toGraphQLError(err)
	}

	return result, nil
}

func resolvePageInfoHasPrevious(p graphql.ResolveParams) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil {
		return false, nil
	}

	if c.backward {
		return c.hasMore, nil
	}

	result, err := c.hasOtherPage()
	if err != nil {
		return nil, toGraphQLError(err)
	}

	return result, nil
}

func resolvePageInfoStartCursor(p graphql.ResolveParams) (any, error) {
	return pageInfoCursor(p, 0)
}

func resolvePageInfoEndCursor(p graphql.ResolveParams) (any, error) {
	return pageInfoCursor(p, -1)
}

func pageInfoCursor(p graphql.ResolveParams, index int) (any, error) {
	c, _ := p.Source.(*graphqlConnection)
	if c == nil || len(c.records) == 0 {
		return nil, nil
	}

	if index < 0 {
		index = len(c.records) + index
	}

	cursor, err := c.cursorFor(c.records[index])
	if err != nil {
		return nil, toGraphQLError(err)
	}

	return cursor, nil
}

func base64URLEncode(str string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(str))
}

func base64URLDecode(str string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(str)
	return string(decoded), err
}
