package apis

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/dbutils"
	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/types"
)

const graphqlSchemaStoreKey = "__pbGraphQLSchema__"

var graphqlNameRegex = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

// graphqlReservedTypeNames are the built-in and the shared schema type names.
var graphqlReservedTypeNames = []string{
	"Query", "Mutation", "Subscription", "Node", "PageInfo", "File", "GeoPoint", "DateTime", "JSON",
	"ID", "String", "Int", "Float", "Boolean",
}

// graphqlReservedRootFields are the shared root query field names.
var graphqlReservedRootFields = []string{"node"}

// graphqlSchema is the GraphQL schema generated from the collections
// (it is cached and rebuilt when the cached collections are reloaded).
type graphqlSchema struct {
	schema graphql.Schema

	// collections is the cached collections slice the schema was built from
	collections []*core.Collection

	types       map[string]*graphqlCollectionType // by collection name
	typesByName map[string]*graphqlCollectionType // by GraphQL type name
	connections map[string]*graphqlCollectionType // by GraphQL connection type name

	// multiRelations is the max number of related records per "TypeName.fieldName" list field
	multiRelations map[string]int

	report []*graphqlCollectionInfo
}

// graphqlCollectionType describes the GraphQL types of a single collection.
type graphqlCollectionType struct {
	collection *core.Collection

	typeName      string
	singularField string
	pluralField   string

	object     *graphql.Object
	connection *graphql.Object
	edge       *graphql.Object

	// fields maps the GraphQL field names to the collection fields (without id)
	fields map[string]core.Field

	// uniqueArgs maps the singular query arguments to the collection unique field names (without id)
	uniqueArgs map[string]string

	// sortable is the list of the collection fields allowed in the connection sort
	sortable map[string]core.Field
}

// graphqlCollectionInfo is the GraphQL mapping report of a single collection (see the dashboard collection panel).
type graphqlCollectionInfo struct {
	CollectionId   string              `json:"collectionId"`
	CollectionName string              `json:"collectionName"`
	Included       bool                `json:"included"`
	Reason         string              `json:"reason,omitempty"`
	TypeName       string              `json:"typeName,omitempty"`
	SingularField  string              `json:"singularField,omitempty"`
	PluralField    string              `json:"pluralField,omitempty"`
	UniqueArgs     []string            `json:"uniqueArgs"`
	SortFields     []string            `json:"sortFields"`
	Fields         []*graphqlFieldInfo `json:"fields"`
}

type graphqlFieldInfo struct {
	Name   string `json:"name"`
	Field  string `json:"field,omitempty"`
	Type   string `json:"type,omitempty"`
	Reason string `json:"reason,omitempty"`
}

var graphqlSchemaMu sync.Mutex

// graphqlSchemaFor returns the GraphQL schema of the current app collections
// (cached until the next collections cache reload).
func graphqlSchemaFor(app core.App) (*graphqlSchema, error) {
	collections, _ := app.Store().Get(core.StoreKeyCachedCollections).([]*core.Collection)

	graphqlSchemaMu.Lock()
	defer graphqlSchemaMu.Unlock()

	cached, _ := app.Store().Get(graphqlSchemaStoreKey).(*graphqlSchema)
	if cached != nil && sameCollectionsSlice(cached.collections, collections) {
		return cached, nil
	}

	s, err := newGraphQLSchema(app, collections)
	if err != nil {
		return nil, err
	}

	app.Store().Set(graphqlSchemaStoreKey, s)

	return s, nil
}

// sameCollectionsSlice reports whether a and b are the same slice
// (the collections cache is replaced with a new slice on every reload).
func sameCollectionsSlice(a, b []*core.Collection) bool {
	if len(a) != len(b) {
		return false
	}

	return len(a) == 0 || &a[0] == &b[0]
}

func newGraphQLSchema(app core.App, collections []*core.Collection) (*graphqlSchema, error) {
	s := &graphqlSchema{
		collections:    collections,
		types:          map[string]*graphqlCollectionType{},
		typesByName:    map[string]*graphqlCollectionType{},
		connections:    map[string]*graphqlCollectionType{},
		multiRelations: map[string]int{},
		report:         []*graphqlCollectionInfo{},
	}

	candidates := s.resolveCollectionNames(app, collections)

	nodeInterface := graphql.NewInterface(graphql.InterfaceConfig{
		Name:        "Node",
		Description: "An object with a global ID.",
		Fields: graphql.Fields{
			"id": &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
		},
		ResolveType: func(p graphql.ResolveTypeParams) *graphql.Object {
			if r, ok := p.Value.(*graphqlRecord); ok {
				if t := s.types[r.record.Collection().Name]; t != nil {
					return t.object
				}
			}
			return nil
		},
	})

	for _, t := range candidates {
		s.buildCollectionTypes(app, t, nodeInterface)
	}

	queryFields := graphql.Fields{
		"node": &graphql.Field{
			Type:        nodeInterface,
			Description: "Fetches a single record by its global ID.",
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)},
			},
			Resolve: s.resolveNode,
		},
	}

	for _, t := range candidates {
		queryFields[t.singularField] = s.singularQueryField(t)
		queryFields[t.pluralField] = s.pluralQueryField(t)
	}

	objectTypes := make([]graphql.Type, 0, len(candidates))
	for _, t := range candidates {
		objectTypes = append(objectTypes, t.object)
	}

	schema, err := graphql.NewSchema(graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{
			Name:   "Query",
			Fields: queryFields,
		}),
		Types: objectTypes,
	})
	if err != nil {
		return nil, err
	}

	s.schema = schema

	return s, nil
}

// resolveCollectionNames resolves the GraphQL names of the regular collections
// with List or View API rule and returns the ones without name collisions.
func (s *graphqlSchema) resolveCollectionNames(app core.App, collections []*core.Collection) []*graphqlCollectionType {
	candidates := []*graphqlCollectionType{}

	for _, c := range collections {
		if c.System {
			continue
		}

		info := &graphqlCollectionInfo{
			CollectionId:   c.Id,
			CollectionName: c.Name,
			UniqueArgs:     []string{},
			SortFields:     []string{},
			Fields:         []*graphqlFieldInfo{},
		}
		s.report = append(s.report, info)

		if c.ListRule == nil && c.ViewRule == nil {
			info.Reason = "The collection has no List or View API rule (staff only)."
			continue
		}

		singular := inflector.Singularize(c.Name)
		plural := inflector.Pluralize(singular)

		t := &graphqlCollectionType{
			collection:    c,
			typeName:      inflector.Camelize(singular),
			singularField: graphqlLcFirst(inflector.Camelize(singular)),
			pluralField:   graphqlLcFirst(inflector.Camelize(plural)),
		}
		if t.pluralField == t.singularField {
			t.pluralField += "List"
		}

		info.TypeName = t.typeName
		info.SingularField = t.singularField
		info.PluralField = t.pluralField

		if !graphqlIsValidName(t.typeName) || !graphqlIsValidName(t.singularField) || !graphqlIsValidName(t.pluralField) {
			info.Reason = "The collection name can't be converted to a valid GraphQL name."
			continue
		}

		candidates = append(candidates, t)
	}

	// detect the name collisions (with the reserved names or with another collection)
	owners := map[string][]*graphqlCollectionType{}
	for _, t := range candidates {
		for _, name := range []string{
			"type:" + t.typeName,
			"type:" + t.typeName + "Connection",
			"type:" + t.typeName + "Edge",
			"field:" + t.singularField,
			"field:" + t.pluralField,
		} {
			owners[name] = append(owners[name], t)
		}
	}

	collisions := map[*graphqlCollectionType][]string{}
	for name, list := range owners {
		kind, value, _ := strings.Cut(name, ":")

		reserved := (kind == "type" && slices.Contains(graphqlReservedTypeNames, value)) ||
			(kind == "field" && slices.Contains(graphqlReservedRootFields, value))

		if len(list) < 2 && !reserved {
			continue
		}

		for _, t := range list {
			if reserved {
				collisions[t] = append(collisions[t], "reserved name "+value)
			}
			for _, other := range list {
				if other != t {
					collisions[t] = append(collisions[t], "collection "+other.collection.Name)
				}
			}
		}
	}

	result := make([]*graphqlCollectionType, 0, len(candidates))
	for _, t := range candidates {
		if reasons := collisions[t]; len(reasons) > 0 {
			slices.Sort(reasons)
			reason := "GraphQL name collision with " + strings.Join(slices.Compact(reasons), ", ") + "."

			app.Logger().Warn("GraphQL: collection skipped", "collection", t.collection.Name, "reason", reason)

			s.findReport(t.collection.Id).Reason = reason
			continue
		}

		s.findReport(t.collection.Id).Included = true

		s.types[t.collection.Name] = t
		s.typesByName[t.typeName] = t
		s.connections[t.typeName+"Connection"] = t

		result = append(result, t)
	}

	return result
}

func (s *graphqlSchema) findReport(collectionId string) *graphqlCollectionInfo {
	for _, info := range s.report {
		if info.CollectionId == collectionId {
			return info
		}
	}

	return &graphqlCollectionInfo{}
}

func (s *graphqlSchema) buildCollectionTypes(app core.App, t *graphqlCollectionType, nodeInterface *graphql.Interface) {
	collection := t.collection
	info := s.findReport(collection.Id)

	t.fields = map[string]core.Field{}
	t.uniqueArgs = map[string]string{}
	t.sortable = map[string]core.Field{}

	secrets := core.SecretFieldNames(collection)

	// resolve the field names in the collection fields order (the colliding fields are skipped)
	fieldInfos := make(map[string]*graphqlFieldInfo, len(collection.Fields))
	fieldOwners := map[string][]core.Field{}
	for _, f := range collection.Fields {
		name := f.GetName()

		fi := &graphqlFieldInfo{Field: name}
		info.Fields = append(info.Fields, fi)
		fieldInfos[name] = fi

		switch {
		case name == core.FieldNameId:
			fi.Name = "id"
			fi.Type = "ID!"
		case f.GetHidden() || f.Type() == core.FieldTypePassword || slices.Contains(secrets, name):
			fi.Reason = "hidden or secret field"
		default:
			gqlName := graphqlLcFirst(inflector.Camelize(name))
			if !graphqlIsValidName(gqlName) {
				fi.Reason = "invalid GraphQL name"
				continue
			}

			fi.Name = gqlName
			fieldOwners[gqlName] = append(fieldOwners[gqlName], f)
		}
	}

	for gqlName, owners := range fieldOwners {
		if len(owners) > 1 || gqlName == "id" {
			for _, f := range owners {
				fi := fieldInfos[f.GetName()]
				fi.Name = ""
				fi.Reason = "GraphQL name collision (" + gqlName + ")"
				app.Logger().Warn("GraphQL: field skipped", "collection", collection.Name, "field", f.GetName(), "reason", fi.Reason)
			}
			continue
		}

		f := owners[0]
		t.fields[gqlName] = f

		switch f.Type() {
		case core.FieldTypeText, core.FieldTypeEmail, core.FieldTypeURL:
			if _, ok := dbutils.FindSingleColumnUniqueIndex(collection.Indexes, f.GetName()); ok {
				t.uniqueArgs[gqlName] = f.GetName()
				info.UniqueArgs = append(info.UniqueArgs, gqlName)
			}
		}

		if graphqlIsSortableField(f) {
			t.sortable[f.GetName()] = f
		}
	}
	t.sortable[core.FieldNameId] = collection.Fields.GetByName(core.FieldNameId)

	for name := range t.sortable {
		info.SortFields = append(info.SortFields, name)
	}
	sort.Strings(info.SortFields)
	sort.Strings(info.UniqueArgs)

	t.object = graphql.NewObject(graphql.ObjectConfig{
		Name:        t.typeName,
		Description: "Record of the " + collection.Name + " collection.",
		Interfaces:  []*graphql.Interface{nodeInterface},
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			fields := graphql.Fields{
				"id": &graphql.Field{
					Type:        graphql.NewNonNull(graphql.ID),
					Description: "The global ID (see Query.node).",
					Resolve: func(p graphql.ResolveParams) (any, error) {
						r, _ := p.Source.(*graphqlRecord)
						if r == nil {
							return nil, nil
						}
						return graphqlGlobalId(r.record.Collection().Name, r.record.Id), nil
					},
				},
			}

			for gqlName, f := range t.fields {
				fields[gqlName] = s.recordField(t, gqlName, f, fieldInfos[f.GetName()])
			}

			return fields
		}),
	})

	t.edge = graphql.NewObject(graphql.ObjectConfig{
		Name: t.typeName + "Edge",
		Fields: graphql.Fields{
			"cursor": &graphql.Field{Type: graphql.NewNonNull(graphql.String), Resolve: resolveEdgeCursor},
			"node":   &graphql.Field{Type: graphql.NewNonNull(t.object), Resolve: resolveEdgeNode},
		},
	})

	t.connection = graphql.NewObject(graphql.ObjectConfig{
		Name: t.typeName + "Connection",
		Fields: graphql.Fields{
			"edges":      &graphql.Field{Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(t.edge))), Resolve: resolveConnectionEdges},
			"nodes":      &graphql.Field{Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(t.object))), Resolve: resolveConnectionNodes},
			"pageInfo":   &graphql.Field{Type: graphql.NewNonNull(graphqlPageInfoType), Resolve: resolveConnectionPageInfo},
			"totalCount": &graphql.Field{Type: graphql.NewNonNull(graphql.Int), Resolve: resolveConnectionTotalCount},
		},
	})
}

// recordField returns the GraphQL field definition of a single collection field
// (and updates the field report type).
func (s *graphqlSchema) recordField(t *graphqlCollectionType, gqlName string, f core.Field, info *graphqlFieldInfo) *graphql.Field {
	name := f.GetName()

	field := &graphql.Field{}

	switch f := f.(type) {
	case *core.NumberField:
		field.Type = graphql.Float
		field.Resolve = graphqlValueResolver(name, func(v any) any { return v })
	case *core.BoolField:
		field.Type = graphql.Boolean
		field.Resolve = graphqlValueResolver(name, func(v any) any { return v })
	case *core.DateField, *core.AutodateField:
		field.Type = graphqlDateTimeType
		field.Resolve = graphqlValueResolver(name, graphqlDateTimeValue)
	case *core.SelectField:
		if f.IsMultiple() {
			field.Type = graphql.NewList(graphql.NewNonNull(graphql.String))
		} else {
			field.Type = graphql.String
		}
		field.Resolve = graphqlValueResolver(name, func(v any) any { return v })
	case *core.JSONField:
		field.Type = graphqlJSONType
		field.Resolve = graphqlValueResolver(name, graphqlJSONValue)
	case *core.GeoPointField:
		field.Type = graphqlGeoPointType
		field.Resolve = graphqlValueResolver(name, func(v any) any { return v })
	case *core.FileField:
		if f.IsMultiple() {
			field.Type = graphql.NewList(graphql.NewNonNull(graphqlFileType))
		} else {
			field.Type = graphqlFileType
		}
		field.Resolve = resolveRecordFiles(name, f.IsMultiple(), f.Protected)
	case *core.RelationField:
		target, ok := s.relationTarget(f)
		if ok {
			if f.IsMultiple() {
				field.Type = graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(target.object)))
				s.multiRelations[t.typeName+"."+gqlName] = f.MaxSelect
			} else {
				field.Type = target.object
			}
			field.Resolve = resolveRecordRelation(name, target.collection, f.IsMultiple())
		} else {
			if f.IsMultiple() {
				field.Type = graphql.NewList(graphql.NewNonNull(graphql.ID))
			} else {
				field.Type = graphql.ID
			}
			field.Resolve = graphqlValueResolver(name, graphqlEmptyStringAsNil)
		}
	case *core.TextField, *core.EmailField, *core.URLField, *core.EditorField:
		field.Type = graphql.String
		field.Resolve = graphqlValueResolver(name, func(v any) any { return v })
	default:
		// custom (aka. plugin) fields
		field.Type = graphqlJSONType
		field.Resolve = graphqlValueResolver(name, graphqlJSONValue)
	}

	info.Type = field.Type.String()

	return field
}

func (s *graphqlSchema) relationTarget(f *core.RelationField) (*graphqlCollectionType, bool) {
	for _, t := range s.types {
		if t.collection.Id == f.CollectionId {
			return t, true
		}
	}

	return nil, false
}

// graphqlIsSortableField reports whether the field could be used in the connections sort
// (the keyset pagination requires stable local scalar values).
func graphqlIsSortableField(f core.Field) bool {
	switch f := f.(type) {
	case *core.TextField, *core.EmailField, *core.URLField, *core.EditorField,
		*core.NumberField, *core.BoolField, *core.DateField, *core.AutodateField:
		return true
	case *core.SelectField:
		return !f.IsMultiple()
	}

	return false
}

func graphqlIsValidName(name string) bool {
	return graphqlNameRegex.MatchString(name) && !strings.HasPrefix(name, "__")
}

func graphqlLcFirst(str string) string {
	if str == "" {
		return str
	}

	r, size := utf8.DecodeRuneInString(str)

	return string(unicode.ToLower(r)) + str[size:]
}

// -------------------------------------------------------------------
// Shared types
// -------------------------------------------------------------------

var graphqlDateTimeType = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "DateTime",
	Description: "RFC3339 date time string.",
	Serialize: func(value any) any {
		return value
	},
	ParseValue: func(value any) any {
		return value
	},
	ParseLiteral: func(valueAST ast.Value) any {
		if v, ok := valueAST.(*ast.StringValue); ok {
			return v.Value
		}
		return nil
	},
})

var graphqlJSONType = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "JSON",
	Description: "Arbitrary JSON value.",
	Serialize: func(value any) any {
		return value
	},
	ParseValue: func(value any) any {
		return value
	},
	ParseLiteral: graphqlParseJSONLiteral,
})

func graphqlParseJSONLiteral(valueAST ast.Value) any {
	switch v := valueAST.(type) {
	case *ast.StringValue:
		return v.Value
	case *ast.BooleanValue:
		return v.Value
	case *ast.IntValue, *ast.FloatValue:
		var n float64
		_ = json.Unmarshal([]byte(v.GetValue().(string)), &n)
		return n
	case *ast.ListValue:
		result := make([]any, len(v.Values))
		for i, item := range v.Values {
			result[i] = graphqlParseJSONLiteral(item)
		}
		return result
	case *ast.ObjectValue:
		result := make(map[string]any, len(v.Fields))
		for _, f := range v.Fields {
			result[f.Name.Value] = graphqlParseJSONLiteral(f.Value)
		}
		return result
	}

	return nil
}

var graphqlGeoPointType = graphql.NewObject(graphql.ObjectConfig{
	Name: "GeoPoint",
	Fields: graphql.Fields{
		"lon": &graphql.Field{Type: graphql.NewNonNull(graphql.Float)},
		"lat": &graphql.Field{Type: graphql.NewNonNull(graphql.Float)},
	},
})

var graphqlFileType = graphql.NewObject(graphql.ObjectConfig{
	Name: "File",
	Fields: graphql.Fields{
		"filename": &graphql.Field{Type: graphql.NewNonNull(graphql.String), Resolve: resolveFileName},
		"url": &graphql.Field{
			Type:        graphql.String,
			Description: "The file URL (the protected files require a file token, see /api/files/token).",
			Args: graphql.FieldConfigArgument{
				"token": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: resolveFileURL,
		},
	},
})

var graphqlPageInfoType = graphql.NewObject(graphql.ObjectConfig{
	Name: "PageInfo",
	Fields: graphql.Fields{
		"hasNextPage":     &graphql.Field{Type: graphql.NewNonNull(graphql.Boolean), Resolve: resolvePageInfoHasNext},
		"hasPreviousPage": &graphql.Field{Type: graphql.NewNonNull(graphql.Boolean), Resolve: resolvePageInfoHasPrevious},
		"startCursor":     &graphql.Field{Type: graphql.String, Resolve: resolvePageInfoStartCursor},
		"endCursor":       &graphql.Field{Type: graphql.String, Resolve: resolvePageInfoEndCursor},
	},
})

// -------------------------------------------------------------------
// Scalar values
// -------------------------------------------------------------------

func graphqlDateTimeValue(v any) any {
	dt, ok := v.(types.DateTime)
	if !ok || dt.IsZero() {
		return nil
	}

	return dt.Time().UTC().Format(time.RFC3339Nano)
}

func graphqlJSONValue(v any) any {
	raw, ok := v.(types.JSONRaw)
	if !ok {
		return v
	}

	if len(raw) == 0 {
		return nil
	}

	var result any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil
	}

	return result
}

func graphqlEmptyStringAsNil(v any) any {
	if s, ok := v.(string); ok && s == "" {
		return nil
	}

	return v
}

// graphqlGlobalId returns the global (aka. Node) ID of a record.
func graphqlGlobalId(collectionName string, recordId string) string {
	return base64URLEncode(collectionName + ":" + recordId)
}

// parseGraphQLGlobalId returns the collection name and the record id of a global ID.
func parseGraphQLGlobalId(globalId string) (string, string, error) {
	decoded, err := base64URLDecode(globalId)
	if err != nil {
		return "", "", err
	}

	collectionName, recordId, ok := strings.Cut(decoded, ":")
	if !ok || collectionName == "" || recordId == "" {
		return "", "", fmt.Errorf("invalid global id %q", globalId)
	}

	return collectionName, recordId, nil
}
