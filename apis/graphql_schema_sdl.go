package apis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/location"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/dbutils"
	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// GraphQL schema editor: the SDL of the managed (non-system and non-view) collections.
//
// The SDL is a declarative description of the collection names, types, rules, indexes and
// fields: it is parsed against the current collections into target collection models and the
// plan is their diff. Everything else (auth options, templates, field ids, system fields) stays
// as it is. A field is matched by its name (a rename is a removal + addition).

const graphqlSDLDefaultMultiRelation = 999
const graphqlSDLDefaultMultiFile = 99

var graphqlSDLScalars = []string{"String", "Float", "Int", "Boolean", "ID", "DateTime", "JSON", "Email", "URL", "Editor", "File", "GeoPoint"}

// the args of the known directives
var (
	graphqlSDLCollectionArgs = []string{"name", "type"}
	graphqlSDLRulesArgs      = []string{"list", "view", "create", "update", "delete", "auth", "manage"}
	graphqlSDLIndexArgs      = []string{"name", "fields", "unique", "where"}
	graphqlSDLRelationArgs   = []string{"cascadeDelete", "onCollection"}
	graphqlSDLDefaultArgs    = []string{"value"}
)

var graphqlSDLFieldCommonArgs = []string{"name", "help", "presentable", "type"}

var graphqlSDLFieldArgs = map[string][]string{
	core.FieldTypeText:     {"min", "max", "pattern", "autogeneratePattern"},
	core.FieldTypeNumber:   {"min", "max"},
	core.FieldTypeBool:     {},
	core.FieldTypeEmail:    {"exceptDomains", "onlyDomains"},
	core.FieldTypeURL:      {"exceptDomains", "onlyDomains"},
	core.FieldTypeEditor:   {"maxSize", "convertURLs"},
	core.FieldTypeDate:     {"min", "max"},
	core.FieldTypeAutodate: {"onCreate", "onUpdate"},
	core.FieldTypeSelect:   {"values", "max"},
	core.FieldTypeFile:     {"max", "maxSize", "mimeTypes", "thumbs", "protected"},
	core.FieldTypeRelation: {"min", "max"},
	core.FieldTypeJSON:     {"maxSize"},
	core.FieldTypePassword: {"min", "max", "pattern", "cost"},
	core.FieldTypeGeoPoint: {},
}

// graphqlSchemaError is a schema editor error with its source location (0 when it isn't related to a position).
type graphqlSchemaError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

type graphqlSchemaFieldChange struct {
	Name        string `json:"name"`
	Action      string `json:"action"` // add, update or remove
	Type        string `json:"type"`
	Destructive bool   `json:"destructive"`
}

type graphqlSchemaChange struct {
	Collection  string                     `json:"collection"`
	Action      string                     `json:"action"` // create, update or delete
	Fields      []graphqlSchemaFieldChange `json:"fields"`
	Details     []string                   `json:"details"` // rules, indexes
	Destructive bool                       `json:"destructive"`
}

type graphqlSchemaPlan struct {
	Changes  []graphqlSchemaChange `json:"changes"`
	Warnings []string              `json:"warnings"`
	Errors   []graphqlSchemaError  `json:"errors"`
	PlanHash string                `json:"planHash"`
	CanApply bool                  `json:"canApply"`

	upsert []*core.Collection
	remove []*core.Collection
}

func (p *graphqlSchemaPlan) isDestructive() bool {
	return slices.ContainsFunc(p.Changes, func(c graphqlSchemaChange) bool { return c.Destructive })
}

// graphqlSDLManagedCollections returns the collections that the SDL describes.
func graphqlSDLManagedCollections(app core.App) ([]*core.Collection, error) {
	all, err := app.FindAllCollections()
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(all, func(c *core.Collection) bool { return c.System || c.IsView() }), nil
}

// -------------------------------------------------------------------
// Names
// -------------------------------------------------------------------

func graphqlSDLCollectionNameOf(typeName string) string {
	return inflector.Pluralize(inflector.Snakecase(typeName))
}

func graphqlSDLFieldNameOf(fieldName string) string {
	return inflector.Snakecase(fieldName)
}

func graphqlSDLTypeNames(collections []*core.Collection) map[string]string {
	result := make(map[string]string, len(collections))
	used := map[string]struct{}{}
	for _, n := range graphqlSDLScalars {
		used[n] = struct{}{}
	}
	for _, n := range graphqlReservedTypeNames {
		used[n] = struct{}{}
	}

	for _, c := range collections {
		base := inflector.Camelize(inflector.Singularize(c.Name))
		if !graphqlIsValidName(base) || strings.HasPrefix(base, "__") {
			base = "C" + strings.TrimLeft(base, "_")
		}

		name := base
		for i := 2; ; i++ {
			if _, ok := used[name]; !ok && graphqlIsValidName(name) {
				break
			}
			name = base + strconv.Itoa(i)
		}

		used[name] = struct{}{}
		result[c.Id] = name
	}

	return result
}

func graphqlSDLFieldAlias(name string, used map[string]struct{}) string {
	base := graphqlLcFirst(inflector.Camelize(name))
	if !graphqlIsValidName(base) || strings.HasPrefix(base, "__") {
		base = "f" + strings.TrimLeft(base, "_")
	}

	alias := base
	for i := 2; ; i++ {
		if _, ok := used[alias]; !ok && graphqlIsValidName(alias) {
			break
		}
		alias = base + "_" + strconv.Itoa(i)
	}

	used[alias] = struct{}{}

	return alias
}

// -------------------------------------------------------------------
// Derive
// -------------------------------------------------------------------

func graphqlSDLString(value string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)

	return strings.TrimSpace(buf.String())
}

func graphqlSDLStrings(values []string) string {
	items := make([]string, len(values))
	for i, v := range values {
		items[i] = graphqlSDLString(v)
	}

	return "[" + strings.Join(items, ", ") + "]"
}

func graphqlSDLFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func graphqlSDLDirective(name string, args []string) string {
	if len(args) == 0 {
		return ""
	}

	return " @" + name + "(" + strings.Join(args, ", ") + ")"
}

func graphqlSDLIndexKey(idx dbutils.Index) string {
	columns := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		columns[i] = strings.ToLower(strings.TrimSpace(c.Name + " " + c.Collate + " " + c.Sort))
	}

	return strings.ToLower(idx.IndexName) + "|" + strconv.FormatBool(idx.Unique) + "|" + strings.Join(columns, ",") + "|" + strings.TrimSpace(idx.Where)
}

// graphqlSDLIsSystemIndex reports whether all columns of the index are system fields
// (e.g. the auth collections tokenKey and email indexes; they are maintained by the collection model).
func graphqlSDLIsSystemIndex(c *core.Collection, idx dbutils.Index) bool {
	if len(idx.Columns) == 0 || !c.IsAuth() {
		return false
	}

	for _, column := range idx.Columns {
		f := c.Fields.GetByName(column.Name)
		if f == nil || !f.GetSystem() {
			return false
		}
	}

	return true
}

func graphqlSDLUniqueIndexName(collection string, field string) string {
	return "idx_" + collection + "_" + field
}

func graphqlSDLIndexColumn(column dbutils.IndexColumn) string {
	result := column.Name
	if column.Collate != "" {
		result += " COLLATE " + column.Collate
	}
	if column.Sort != "" {
		result += " " + column.Sort
	}
	return result
}

// graphqlDeriveSchema returns the SDL of the current managed collections.
func graphqlDeriveSchema(app core.App) (string, error) {
	collections, err := graphqlSDLManagedCollections(app)
	if err != nil {
		return "", err
	}

	typeNames := graphqlSDLTypeNames(collections)

	var out strings.Builder
	out.WriteString("# The schema of the collections (the system and view collections are not part of it).\n")

	for _, c := range collections {
		typeName := typeNames[c.Id]

		out.WriteString("\ntype " + typeName)

		collectionArgs := []string{}
		if graphqlSDLCollectionNameOf(typeName) != c.Name {
			collectionArgs = append(collectionArgs, "name: "+graphqlSDLString(c.Name))
		}
		if c.IsAuth() {
			collectionArgs = append(collectionArgs, "type: auth")
		}
		out.WriteString(graphqlSDLDirective("collection", collectionArgs))

		ruleArgs := []string{}
		addRule := func(name string, rule *string) {
			if rule != nil {
				ruleArgs = append(ruleArgs, name+": "+graphqlSDLString(*rule))
			}
		}
		addRule("list", c.ListRule)
		addRule("view", c.ViewRule)
		addRule("create", c.CreateRule)
		addRule("update", c.UpdateRule)
		addRule("delete", c.DeleteRule)
		if c.IsAuth() {
			addRule("auth", c.AuthRule)
			addRule("manage", c.ManageRule)
		}
		out.WriteString(graphqlSDLDirective("rules", ruleArgs))

		// a plain single-column unique index with the conventional name is the field @unique
		uniqueFields := map[string]struct{}{}
		for _, raw := range c.Indexes {
			idx := dbutils.ParseIndex(raw)
			if graphqlSDLIsSystemIndex(c, idx) {
				continue
			}

			if idx.Unique && len(idx.Columns) == 1 && idx.Where == "" && idx.Columns[0].Collate == "" && idx.Columns[0].Sort == "" &&
				strings.EqualFold(idx.IndexName, graphqlSDLUniqueIndexName(c.Name, idx.Columns[0].Name)) {
				uniqueFields[idx.Columns[0].Name] = struct{}{}
				continue
			}

			columns := make([]string, len(idx.Columns))
			for i, column := range idx.Columns {
				columns[i] = graphqlSDLIndexColumn(column)
			}

			args := []string{"name: " + graphqlSDLString(idx.IndexName), "fields: " + graphqlSDLStrings(columns)}
			if idx.Unique {
				args = append(args, "unique: true")
			}
			if idx.Where != "" {
				args = append(args, "where: "+graphqlSDLString(idx.Where))
			}
			out.WriteString(graphqlSDLDirective("index", args))
		}

		out.WriteString(" {\n")

		var enums strings.Builder
		aliases := map[string]struct{}{}

		for _, f := range c.Fields {
			if f.GetSystem() && f.GetName() != core.FieldNameId {
				continue
			}

			alias := graphqlSDLFieldAlias(f.GetName(), aliases)

			fieldType, fieldArgs, extra := graphqlSDLDeriveField(app, f, typeName, alias, typeNames, &enums)

			if graphqlSDLFieldNameOf(alias) != f.GetName() {
				fieldArgs = append([]string{"name: " + graphqlSDLString(f.GetName())}, fieldArgs...)
			}
			if help := graphqlSDLFieldHelp(f); help != "" {
				fieldArgs = append(fieldArgs, "help: "+graphqlSDLString(help))
			}
			if graphqlSDLFieldPresentable(f) {
				fieldArgs = append(fieldArgs, "presentable: true")
			}

			out.WriteString("  " + alias + ": " + fieldType)
			out.WriteString(graphqlSDLDirective("field", fieldArgs))
			out.WriteString(extra)
			if _, ok := uniqueFields[f.GetName()]; ok {
				out.WriteString(" @unique")
			}
			if f.GetHidden() {
				out.WriteString(" @hidden")
			}
			out.WriteString("\n")
		}

		out.WriteString("}\n")
		out.WriteString(enums.String())
	}

	return out.String(), nil
}

func graphqlSDLFieldHelp(f core.Field) string {
	raw, err := json.Marshal(f)
	if err != nil {
		return ""
	}

	data := struct {
		Help string `json:"help"`
	}{}
	_ = json.Unmarshal(raw, &data)

	return data.Help
}

func graphqlSDLFieldPresentable(f core.Field) bool {
	raw, err := json.Marshal(f)
	if err != nil {
		return false
	}

	data := struct {
		Presentable bool `json:"presentable"`
	}{}
	_ = json.Unmarshal(raw, &data)

	return data.Presentable
}

func graphqlSDLSetFieldPresentable(f core.Field, value bool) error {
	return json.Unmarshal([]byte(`{"presentable":`+strconv.FormatBool(value)+`}`), f)
}

func graphqlSDLRequired(name string, required bool) string {
	if required {
		return name + "!"
	}
	return name
}

func graphqlSDLList(name string, required bool) string {
	return graphqlSDLRequired("["+name+"!]", required)
}

// graphqlSDLDeriveField returns the field type, the @field args and the extra directives of the provided field.
func graphqlSDLDeriveField(
	app core.App,
	f core.Field,
	typeName string,
	alias string,
	typeNames map[string]string,
	enums *strings.Builder,
) (string, []string, string) {
	args := []string{}
	extra := ""

	intArg := func(name string, value int64) {
		if value != 0 {
			args = append(args, name+": "+strconv.FormatInt(value, 10))
		}
	}
	strArg := func(name string, value string) {
		if value != "" {
			args = append(args, name+": "+graphqlSDLString(value))
		}
	}
	listArg := func(name string, values []string) {
		if len(values) > 0 {
			args = append(args, name+": "+graphqlSDLStrings(values))
		}
	}
	boolArg := func(name string, value bool) {
		if value {
			args = append(args, name+": true")
		}
	}

	switch field := f.(type) {
	case *core.TextField:
		if field.GetName() == core.FieldNameId {
			if !field.PrimaryKey || field.Min != 15 || field.Max != 15 || field.Pattern != "^[a-z0-9]+$" || field.AutogeneratePattern != "[a-z0-9]{15}" {
				intArg("min", int64(field.Min))
				intArg("max", int64(field.Max))
				strArg("pattern", field.Pattern)
				strArg("autogeneratePattern", field.AutogeneratePattern)
			}
			return "ID!", args, ""
		}
		intArg("min", int64(field.Min))
		intArg("max", int64(field.Max))
		strArg("pattern", field.Pattern)
		strArg("autogeneratePattern", field.AutogeneratePattern)
		return graphqlSDLRequired("String", field.Required), args, ""
	case *core.NumberField:
		if field.Min != nil {
			args = append(args, "min: "+graphqlSDLFloat(*field.Min))
		}
		if field.Max != nil {
			args = append(args, "max: "+graphqlSDLFloat(*field.Max))
		}
		if field.OnlyInt {
			return graphqlSDLRequired("Int", field.Required), args, ""
		}
		return graphqlSDLRequired("Float", field.Required), args, ""
	case *core.BoolField:
		return graphqlSDLRequired("Boolean", field.Required), args, ""
	case *core.EmailField:
		listArg("exceptDomains", field.ExceptDomains)
		listArg("onlyDomains", field.OnlyDomains)
		return graphqlSDLRequired("Email", field.Required), args, ""
	case *core.URLField:
		listArg("exceptDomains", field.ExceptDomains)
		listArg("onlyDomains", field.OnlyDomains)
		return graphqlSDLRequired("URL", field.Required), args, ""
	case *core.EditorField:
		intArg("maxSize", field.MaxSize)
		boolArg("convertURLs", field.ConvertURLs)
		return graphqlSDLRequired("Editor", field.Required), args, ""
	case *core.DateField:
		strArg("min", field.Min.String())
		strArg("max", field.Max.String())
		return graphqlSDLRequired("DateTime", field.Required), args, ""
	case *core.AutodateField:
		boolArg("onCreate", field.OnCreate)
		boolArg("onUpdate", field.OnUpdate)
		return "DateTime", args, ""
	case *core.SelectField:
		isEnum := len(field.Values) > 0
		for _, v := range field.Values {
			if !graphqlIsValidName(v) || v == "true" || v == "false" || v == "null" || strings.HasPrefix(v, "__") {
				isEnum = false
			}
		}

		multiple := field.IsMultiple()
		if multiple && field.MaxSelect != len(field.Values) {
			intArg("max", int64(field.MaxSelect))
		}

		baseType := "String"
		if isEnum {
			baseType = typeName + inflector.UcFirst(alias)
			enums.WriteString("\nenum " + baseType + " {\n")
			for _, v := range field.Values {
				enums.WriteString("  " + v + "\n")
			}
			enums.WriteString("}\n")
		} else {
			args = append([]string{`type: "select"`, "values: " + graphqlSDLStrings(field.Values)}, args...)
		}

		if multiple {
			return graphqlSDLList(baseType, field.Required), args, ""
		}
		return graphqlSDLRequired(baseType, field.Required), args, ""
	case *core.FileField:
		multiple := field.IsMultiple()
		if multiple && field.MaxSelect != graphqlSDLDefaultMultiFile {
			intArg("max", int64(field.MaxSelect))
		}
		intArg("maxSize", field.MaxSize)
		listArg("mimeTypes", field.MimeTypes)
		listArg("thumbs", field.Thumbs)
		boolArg("protected", field.Protected)
		if multiple {
			return graphqlSDLList("File", field.Required), args, ""
		}
		return graphqlSDLRequired("File", field.Required), args, ""
	case *core.RelationField:
		baseType := "ID"
		relationArgs := []string{}
		if target, ok := typeNames[field.CollectionId]; ok {
			baseType = target
		} else if related, err := app.FindCachedCollectionByNameOrId(field.CollectionId); err == nil {
			relationArgs = append(relationArgs, "onCollection: "+graphqlSDLString(related.Name))
		} else {
			relationArgs = append(relationArgs, "onCollection: "+graphqlSDLString(field.CollectionId))
		}
		if field.CascadeDelete {
			relationArgs = append(relationArgs, "cascadeDelete: true")
		}

		intArg("min", int64(field.MinSelect))
		multiple := field.IsMultiple()
		if multiple && field.MaxSelect != graphqlSDLDefaultMultiRelation {
			intArg("max", int64(field.MaxSelect))
		}

		extra = " @relation"
		if len(relationArgs) > 0 {
			extra += "(" + strings.Join(relationArgs, ", ") + ")"
		}

		if multiple {
			return graphqlSDLList(baseType, field.Required), args, extra
		}
		return graphqlSDLRequired(baseType, field.Required), args, extra
	case *core.JSONField:
		intArg("maxSize", field.MaxSize)
		return graphqlSDLRequired("JSON", field.Required), args, ""
	case *core.PasswordField:
		args = append(args, `type: "password"`)
		intArg("min", int64(field.Min))
		intArg("max", int64(field.Max))
		strArg("pattern", field.Pattern)
		intArg("cost", int64(field.Cost))
		return graphqlSDLRequired("String", field.Required), args, ""
	case *core.GeoPointField:
		return graphqlSDLRequired("GeoPoint", field.Required), args, ""
	}

	return "JSON", args, ""
}

// -------------------------------------------------------------------
// Parse
// -------------------------------------------------------------------

type graphqlSDLParser struct {
	app     core.App
	source  *source.Source
	errors  []graphqlSchemaError
	current map[string]*core.Collection // by name

	enums map[string][]string
	types map[string]*graphqlSDLType // by type name
}

type graphqlSDLType struct {
	def        *ast.ObjectDefinition
	collection string // the collection name
	kind       string
	id         string
}

func (p *graphqlSDLParser) errorAt(loc *ast.Location, format string, args ...any) {
	result := graphqlSchemaError{Message: fmt.Sprintf(format, args...)}
	if loc != nil {
		l := location.GetLocation(p.source, loc.Start)
		result.Line = l.Line
		result.Column = l.Column
	}
	p.errors = append(p.errors, result)
}

func graphqlSDLDirectiveByName(directives []*ast.Directive, name string) *ast.Directive {
	for _, d := range directives {
		if d.Name != nil && d.Name.Value == name {
			return d
		}
	}
	return nil
}

func graphqlSDLValue(value ast.Value) any {
	switch v := value.(type) {
	case *ast.StringValue:
		return v.Value
	case *ast.IntValue:
		n, err := strconv.ParseInt(v.Value, 10, 64)
		if err != nil {
			return nil
		}
		return n
	case *ast.FloatValue:
		n, err := strconv.ParseFloat(v.Value, 64)
		if err != nil {
			return nil
		}
		return n
	case *ast.BooleanValue:
		return v.Value
	case *ast.EnumValue:
		return v.Value
	case *ast.ListValue:
		result := make([]any, 0, len(v.Values))
		for _, item := range v.Values {
			result = append(result, graphqlSDLValue(item))
		}
		return result
	}
	return nil
}

// args returns the directive args after checking that they are known.
func (p *graphqlSDLParser) args(d *ast.Directive, allowed []string) map[string]any {
	result := map[string]any{}
	if d == nil {
		return result
	}

	for _, arg := range d.Arguments {
		if !slices.Contains(allowed, arg.Name.Value) {
			p.errorAt(arg.Loc, "Unknown @%s argument %q.", d.Name.Value, arg.Name.Value)
			continue
		}
		result[arg.Name.Value] = graphqlSDLValue(arg.Value)
	}

	return result
}

func graphqlSDLArgString(args map[string]any, name string) string {
	v, _ := args[name].(string)
	return v
}

func graphqlSDLArgInt(args map[string]any, name string) int64 {
	switch v := args[name].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

func graphqlSDLArgFloat(args map[string]any, name string) *float64 {
	switch v := args[name].(type) {
	case int64:
		f := float64(v)
		return &f
	case float64:
		return &v
	}
	return nil
}

func graphqlSDLArgBool(args map[string]any, name string) bool {
	v, _ := args[name].(bool)
	return v
}

func graphqlSDLArgStrings(args map[string]any, name string) []string {
	items, _ := args[name].([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if v, ok := item.(string); ok {
			result = append(result, v)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// graphqlParseSchema returns the target collections of the provided SDL
// (the managed collections missing from the SDL are returned separately).
func graphqlParseSchema(app core.App, schema string) ([]*core.Collection, []*core.Collection, []graphqlSchemaError, []string) {
	p := &graphqlSDLParser{
		app:     app,
		source:  source.NewSource(&source.Source{Body: []byte(schema), Name: "schema"}),
		current: map[string]*core.Collection{},
		enums:   map[string][]string{},
		types:   map[string]*graphqlSDLType{},
	}

	doc, err := parser.Parse(parser.ParseParams{Source: p.source})
	if err != nil {
		var gqlErr *gqlerrors.Error
		if errors.As(err, &gqlErr) && len(gqlErr.Locations) > 0 {
			return nil, nil, []graphqlSchemaError{{Line: gqlErr.Locations[0].Line, Column: gqlErr.Locations[0].Column, Message: gqlErr.Message}}, nil
		}
		return nil, nil, []graphqlSchemaError{{Message: err.Error()}}, nil
	}

	all, findErr := app.FindAllCollections()
	if findErr != nil {
		return nil, nil, []graphqlSchemaError{{Message: findErr.Error()}}, nil
	}
	for _, c := range all {
		p.current[c.Name] = c
	}

	order := []string{}
	for _, node := range doc.Definitions {
		switch def := node.(type) {
		case *ast.ObjectDefinition:
			if _, ok := p.types[def.Name.Value]; ok {
				p.errorAt(def.Loc, "Duplicated type %s.", def.Name.Value)
				continue
			}
			if slices.Contains(graphqlSDLScalars, def.Name.Value) {
				p.errorAt(def.Loc, "The type name %s is reserved.", def.Name.Value)
				continue
			}
			p.types[def.Name.Value] = &graphqlSDLType{def: def}
			order = append(order, def.Name.Value)
		case *ast.EnumDefinition:
			values := make([]string, len(def.Values))
			for i, v := range def.Values {
				values[i] = v.Name.Value
			}
			if _, ok := p.enums[def.Name.Value]; ok {
				p.errorAt(def.Loc, "Duplicated enum %s.", def.Name.Value)
				continue
			}
			p.enums[def.Name.Value] = values
		case *ast.ScalarDefinition, *ast.DirectiveDefinition:
			// the documentation of the scalars and directives (they have a fixed meaning)
		default:
			p.errorAt(node.GetLoc(), "Only type, enum, scalar and directive definitions are supported.")
		}
	}

	seen := map[string]string{}
	warnings := []string{}
	targets := make([]*core.Collection, 0, len(order))

	// the collection names and ids first since the relations could be circular
	for _, typeName := range order {
		t := p.types[typeName]

		args := p.args(graphqlSDLDirectiveByName(t.def.Directives, "collection"), graphqlSDLCollectionArgs)
		t.collection = graphqlSDLArgString(args, "name")
		if t.collection == "" {
			t.collection = graphqlSDLCollectionNameOf(typeName)
		}

		t.kind = graphqlSDLArgString(args, "type")
		if t.kind == "" {
			t.kind = core.CollectionTypeBase
		}
		if t.kind != core.CollectionTypeBase && t.kind != core.CollectionTypeAuth {
			p.errorAt(t.def.Loc, "Invalid collection type %q of %s (base or auth).", t.kind, typeName)
			continue
		}

		if other, ok := seen[t.collection]; ok {
			p.errorAt(t.def.Loc, "The types %s and %s describe the same collection %q.", other, typeName, t.collection)
			continue
		}
		seen[t.collection] = typeName

		if strings.HasPrefix(t.collection, "_") {
			p.errorAt(t.def.Loc, "The system collection %q can't be declared.", t.collection)
			continue
		}

		if existing := p.current[t.collection]; existing != nil {
			if existing.System {
				p.errorAt(t.def.Loc, "The system collection %q can't be declared.", t.collection)
				continue
			}
			if existing.IsView() {
				p.errorAt(t.def.Loc, "The view collection %q can't be declared.", t.collection)
				continue
			}
			if existing.Type != t.kind {
				p.errorAt(t.def.Loc, "The type of the collection %q can't be changed (%s -> %s).", t.collection, existing.Type, t.kind)
				continue
			}
			t.id = existing.Id
		} else {
			t.id = core.NewCollection(t.kind, t.collection).Id
		}
	}

	if len(p.errors) > 0 {
		return nil, nil, p.errors, nil
	}

	for _, typeName := range order {
		t := p.types[typeName]
		target := p.buildCollection(t)
		targets = append(targets, target)

		if target.ListRule == nil && target.ViewRule == nil {
			warnings = append(warnings, fmt.Sprintf("%s has no list or view rule: it is accessible only by the staff and it is not in the GraphQL API.", t.collection))
		}
	}

	if len(p.errors) > 0 {
		return nil, nil, p.errors, nil
	}

	remove := []*core.Collection{}
	for _, c := range all {
		if !c.System && !c.IsView() {
			if _, ok := seen[c.Name]; !ok {
				remove = append(remove, c)
			}
		}
	}

	return targets, remove, nil, warnings
}

func (p *graphqlSDLParser) buildCollection(t *graphqlSDLType) *core.Collection {
	var target *core.Collection

	if existing := p.current[t.collection]; existing != nil {
		// a deep copy (the found models could be the cached ones)
		target, _ = p.app.FindCollectionByNameOrId(existing.Id)
	} else {
		target = core.NewCollection(t.kind, t.collection)
		target.Id = t.id
	}

	rules := p.args(graphqlSDLDirectiveByName(t.def.Directives, "rules"), graphqlSDLRulesArgs)
	rule := func(name string) *string {
		v, ok := rules[name].(string)
		if !ok {
			return nil
		}
		return &v
	}
	target.ListRule = rule("list")
	target.ViewRule = rule("view")
	target.CreateRule = rule("create")
	target.UpdateRule = rule("update")
	target.DeleteRule = rule("delete")
	if target.IsAuth() {
		target.AuthRule = rule("auth")
		target.ManageRule = rule("manage")
	} else {
		for _, name := range []string{"auth", "manage"} {
			if _, ok := rules[name]; ok {
				p.errorAt(t.def.Loc, "The %s rule is only for the auth collections.", name)
			}
		}
	}

	// fields
	declared := make([]core.Field, 0, len(t.def.Fields))
	declaredNames := map[string]struct{}{}
	uniqueFields := []string{}

	for _, def := range t.def.Fields {
		field, unique := p.buildField(t, target, def)
		if field == nil {
			continue
		}

		if _, ok := declaredNames[field.GetName()]; ok {
			p.errorAt(def.Loc, "Duplicated field %q of the collection %q.", field.GetName(), t.collection)
			continue
		}
		declaredNames[field.GetName()] = struct{}{}

		declared = append(declared, field)
		if unique {
			uniqueFields = append(uniqueFields, field.GetName())
		}
	}

	// the implicit fields keep their position and the declared ones fill the others
	finalFields := make([]core.Field, 0, len(declared)+4)
	next := 0
	for _, f := range target.Fields {
		if f.GetSystem() {
			if _, ok := declaredNames[f.GetName()]; !ok {
				finalFields = append(finalFields, f)
				continue
			}
		}
		if next < len(declared) {
			finalFields = append(finalFields, declared[next])
			next++
		}
	}
	finalFields = append(finalFields, declared[next:]...)
	target.Fields = core.NewFieldsList(finalFields...)

	// indexes
	tmp := core.NewBaseCollection(t.collection)
	for _, d := range t.def.Directives {
		if d.Name.Value != "index" {
			continue
		}
		args := p.args(d, graphqlSDLIndexArgs)
		name := graphqlSDLArgString(args, "name")
		fields := graphqlSDLArgStrings(args, "fields")
		if name == "" || len(fields) == 0 {
			p.errorAt(d.Loc, "@index requires a name and fields.")
			continue
		}
		tmp.AddIndex(name, graphqlSDLArgBool(args, "unique"), strings.Join(fields, ", "), graphqlSDLArgString(args, "where"))
	}
	for _, name := range uniqueFields {
		tmp.AddIndex(graphqlSDLUniqueIndexName(t.collection, name), true, "`"+name+"`", "")
	}
	indexes := []string(tmp.Indexes)

	keep := []string{}
	oldKeys := []string{}
	for _, raw := range target.Indexes {
		idx := dbutils.ParseIndex(raw)
		if graphqlSDLIsSystemIndex(target, idx) {
			keep = append(keep, raw)
		} else {
			oldKeys = append(oldKeys, graphqlSDLIndexKey(idx))
		}
	}

	newKeys := make([]string, len(indexes))
	for i, raw := range indexes {
		newKeys[i] = graphqlSDLIndexKey(dbutils.ParseIndex(raw))
	}
	slices.Sort(oldKeys)
	slices.Sort(newKeys)
	if !slices.Equal(oldKeys, newKeys) {
		target.Indexes = types.JSONArray[string](append(keep, indexes...))
	}

	return target
}

func graphqlSDLUnwrapType(t ast.Type) (name string, required bool, multiple bool, ok bool) {
	if nonNull, isNonNull := t.(*ast.NonNull); isNonNull {
		required = true
		t = nonNull.Type
	}

	if list, isList := t.(*ast.List); isList {
		multiple = true
		t = list.Type
		if nonNull, isNonNull := t.(*ast.NonNull); isNonNull {
			t = nonNull.Type
		}
	}

	named, isNamed := t.(*ast.Named)
	if !isNamed {
		return "", false, false, false
	}

	return named.Name.Value, required, multiple, true
}

// buildField returns the target field of the provided definition (nil on error) and whether it is @unique.
func (p *graphqlSDLParser) buildField(t *graphqlSDLType, target *core.Collection, def *ast.FieldDefinition) (core.Field, bool) {
	allDirectives := []string{"field", "unique", "hidden", "relation", "default"}
	for _, d := range def.Directives {
		if !slices.Contains(allDirectives, d.Name.Value) {
			p.errorAt(d.Loc, "Unknown directive @%s.", d.Name.Value)
		}
	}

	typeName, required, multiple, ok := graphqlSDLUnwrapType(def.Type)
	if !ok {
		p.errorAt(def.Loc, "Unsupported type of the field %s.", def.Name.Value)
		return nil, false
	}

	fieldDirective := graphqlSDLDirectiveByName(def.Directives, "field")

	// the type specific args are checked below (when the field type is known)
	rawArgs := map[string]any{}
	if fieldDirective != nil {
		for _, arg := range fieldDirective.Arguments {
			rawArgs[arg.Name.Value] = graphqlSDLValue(arg.Value)
		}
	}

	name := graphqlSDLArgString(rawArgs, "name")
	if name == "" {
		name = graphqlSDLFieldNameOf(def.Name.Value)
	}

	if existing := target.Fields.GetByName(name); existing != nil && existing.GetSystem() && name != core.FieldNameId {
		p.errorAt(def.Loc, "The system field %q can't be declared.", name)
		return nil, false
	}

	if name == core.FieldNameId {
		return p.buildIdField(target, def, fieldDirective, rawArgs), false
	}

	explicitType := graphqlSDLArgString(rawArgs, "type")
	relationDirective := graphqlSDLDirectiveByName(def.Directives, "relation")

	var kind string
	relationCollectionId := ""
	values := []string(nil)

	switch {
	case relationDirective != nil || p.types[typeName] != nil:
		kind = core.FieldTypeRelation
		relationArgs := p.args(relationDirective, graphqlSDLRelationArgs)
		onCollection := graphqlSDLArgString(relationArgs, "onCollection")
		if related := p.types[typeName]; related != nil {
			relationCollectionId = related.id
		} else if onCollection != "" {
			if related := p.current[onCollection]; related != nil {
				relationCollectionId = related.Id
			} else if declared := p.findTypeByCollection(onCollection); declared != nil {
				relationCollectionId = declared.id
			}
		}
		if relationCollectionId == "" {
			p.errorAt(def.Loc, "Unknown collection of the relation field %s (use a declared type or @relation(onCollection:)).", def.Name.Value)
			return nil, false
		}
	case p.enums[typeName] != nil:
		kind = core.FieldTypeSelect
		values = p.enums[typeName]
	case explicitType == core.FieldTypeSelect && typeName == "String":
		kind = core.FieldTypeSelect
		values = graphqlSDLArgStrings(rawArgs, "values")
	case explicitType == core.FieldTypePassword && typeName == "String":
		kind = core.FieldTypePassword
	case explicitType != "":
		p.errorAt(def.Loc, "Unsupported @field type %q for %s.", explicitType, typeName)
		return nil, false
	default:
		switch typeName {
		case "String":
			kind = core.FieldTypeText
		case "Float", "Int":
			kind = core.FieldTypeNumber
		case "Boolean":
			kind = core.FieldTypeBool
		case "Email":
			kind = core.FieldTypeEmail
		case "URL":
			kind = core.FieldTypeURL
		case "Editor":
			kind = core.FieldTypeEditor
		case "DateTime":
			kind = core.FieldTypeDate
			if _, ok := rawArgs["onCreate"]; ok {
				kind = core.FieldTypeAutodate
			} else if _, ok := rawArgs["onUpdate"]; ok {
				kind = core.FieldTypeAutodate
			}
		case "JSON":
			kind = core.FieldTypeJSON
		case "File":
			kind = core.FieldTypeFile
		case "GeoPoint":
			kind = core.FieldTypeGeoPoint
		default:
			p.errorAt(def.Loc, "Unknown type %s of the field %s.", typeName, def.Name.Value)
			return nil, false
		}
	}

	if multiple && kind != core.FieldTypeSelect && kind != core.FieldTypeFile && kind != core.FieldTypeRelation {
		p.errorAt(def.Loc, "The field %s can't be a list (only the enums, relations and files).", def.Name.Value)
		return nil, false
	}

	// the allowed args
	for _, arg := range func() []*ast.Argument {
		if fieldDirective == nil {
			return nil
		}
		return fieldDirective.Arguments
	}() {
		if !slices.Contains(graphqlSDLFieldCommonArgs, arg.Name.Value) && !slices.Contains(graphqlSDLFieldArgs[kind], arg.Name.Value) {
			p.errorAt(arg.Loc, "The @field argument %q is not supported for the %s fields.", arg.Name.Value, kind)
		}
	}

	if kind == core.FieldTypeAutodate && required {
		p.errorAt(def.Loc, "The autodate field %s can't be required.", def.Name.Value)
	}

	defaultDirective := graphqlSDLDirectiveByName(def.Directives, "default")
	if defaultDirective != nil && kind != core.FieldTypeText {
		p.errorAt(defaultDirective.Loc, "@default is supported only for the String fields (the collection model has no other default values).")
	}

	existing := target.Fields.GetByName(name)

	base := core.Fields[kind]
	if base == nil {
		p.errorAt(def.Loc, "Unsupported field type %s.", kind)
		return nil, false
	}

	field := base()
	if existing != nil && existing.Type() == kind {
		raw, err := json.Marshal(existing)
		if err == nil {
			err = json.Unmarshal(raw, field)
		}
		if err != nil {
			p.errorAt(def.Loc, "Failed to load the field %s.", def.Name.Value)
			return nil, false
		}
	}

	field.SetName(name)
	field.SetHidden(graphqlSDLDirectiveByName(def.Directives, "hidden") != nil)
	if err := graphqlSDLSetFieldPresentable(field, graphqlSDLArgBool(rawArgs, "presentable")); err != nil {
		p.errorAt(def.Loc, "Failed to load the field %s.", def.Name.Value)
		return nil, false
	}

	setStrings := func(dst *[]string, value []string) {
		if len(value) == 0 && len(*dst) == 0 {
			return
		}
		*dst = value
	}

	help := graphqlSDLArgString(rawArgs, "help")

	switch f := field.(type) {
	case *core.TextField:
		f.Help = help
		f.Required = required
		f.Min = int(graphqlSDLArgInt(rawArgs, "min"))
		f.Max = int(graphqlSDLArgInt(rawArgs, "max"))
		f.Pattern = graphqlSDLArgString(rawArgs, "pattern")
		f.AutogeneratePattern = graphqlSDLArgString(rawArgs, "autogeneratePattern")
		if defaultDirective != nil {
			defaults := p.args(defaultDirective, graphqlSDLDefaultArgs)
			if v, ok := defaults["value"].(string); ok {
				f.AutogeneratePattern = regexp.QuoteMeta(v)
			} else {
				p.errorAt(defaultDirective.Loc, "@default requires a string value.")
			}
		}
	case *core.NumberField:
		f.Help = help
		f.Required = required
		f.OnlyInt = typeName == "Int"
		f.Min = graphqlSDLArgFloat(rawArgs, "min")
		f.Max = graphqlSDLArgFloat(rawArgs, "max")
	case *core.BoolField:
		f.Help = help
		f.Required = required
	case *core.EmailField:
		f.Help = help
		f.Required = required
		setStrings(&f.ExceptDomains, graphqlSDLArgStrings(rawArgs, "exceptDomains"))
		setStrings(&f.OnlyDomains, graphqlSDLArgStrings(rawArgs, "onlyDomains"))
	case *core.URLField:
		f.Help = help
		f.Required = required
		setStrings(&f.ExceptDomains, graphqlSDLArgStrings(rawArgs, "exceptDomains"))
		setStrings(&f.OnlyDomains, graphqlSDLArgStrings(rawArgs, "onlyDomains"))
	case *core.EditorField:
		f.Help = help
		f.Required = required
		f.MaxSize = graphqlSDLArgInt(rawArgs, "maxSize")
		f.ConvertURLs = graphqlSDLArgBool(rawArgs, "convertURLs")
	case *core.DateField:
		f.Help = help
		f.Required = required
		f.Min, _ = types.ParseDateTime(graphqlSDLArgString(rawArgs, "min"))
		f.Max, _ = types.ParseDateTime(graphqlSDLArgString(rawArgs, "max"))
	case *core.AutodateField:
		f.OnCreate = graphqlSDLArgBool(rawArgs, "onCreate")
		f.OnUpdate = graphqlSDLArgBool(rawArgs, "onUpdate")
	case *core.SelectField:
		f.Help = help
		f.Required = required
		f.Values = values
		max := int(graphqlSDLArgInt(rawArgs, "max"))
		switch {
		case multiple && max > 0:
			f.MaxSelect = max
		case multiple:
			f.MaxSelect = len(values)
		case f.MaxSelect > 1 || f.MaxSelect == 0:
			f.MaxSelect = 1
		}
	case *core.FileField:
		f.Help = help
		f.Required = required
		f.MaxSize = graphqlSDLArgInt(rawArgs, "maxSize")
		f.Protected = graphqlSDLArgBool(rawArgs, "protected")
		setStrings(&f.MimeTypes, graphqlSDLArgStrings(rawArgs, "mimeTypes"))
		setStrings(&f.Thumbs, graphqlSDLArgStrings(rawArgs, "thumbs"))
		max := int(graphqlSDLArgInt(rawArgs, "max"))
		switch {
		case multiple && max > 0:
			f.MaxSelect = max
		case multiple:
			f.MaxSelect = graphqlSDLDefaultMultiFile
		case f.MaxSelect > 1 || f.MaxSelect == 0:
			f.MaxSelect = 1
		}
	case *core.RelationField:
		f.Help = help
		f.Required = required
		f.CollectionId = relationCollectionId
		relationArgs := map[string]any{}
		if relationDirective != nil {
			relationArgs = p.args(relationDirective, graphqlSDLRelationArgs)
		}
		f.CascadeDelete = graphqlSDLArgBool(relationArgs, "cascadeDelete")
		f.MinSelect = int(graphqlSDLArgInt(rawArgs, "min"))
		max := int(graphqlSDLArgInt(rawArgs, "max"))
		switch {
		case multiple && max > 0:
			f.MaxSelect = max
		case multiple:
			f.MaxSelect = graphqlSDLDefaultMultiRelation
		case f.MaxSelect > 1 || f.MaxSelect == 0:
			f.MaxSelect = 1
		}
	case *core.JSONField:
		f.Help = help
		f.Required = required
		f.MaxSize = graphqlSDLArgInt(rawArgs, "maxSize")
	case *core.PasswordField:
		f.Help = help
		f.Required = required
		f.Min = int(graphqlSDLArgInt(rawArgs, "min"))
		f.Max = int(graphqlSDLArgInt(rawArgs, "max"))
		f.Pattern = graphqlSDLArgString(rawArgs, "pattern")
		f.Cost = int(graphqlSDLArgInt(rawArgs, "cost"))
	case *core.GeoPointField:
		f.Help = help
		f.Required = required
	}

	return field, graphqlSDLDirectiveByName(def.Directives, "unique") != nil
}

func (p *graphqlSDLParser) findTypeByCollection(name string) *graphqlSDLType {
	for _, t := range p.types {
		if t.collection == name {
			return t
		}
	}
	return nil
}

func (p *graphqlSDLParser) buildIdField(target *core.Collection, def *ast.FieldDefinition, directive *ast.Directive, args map[string]any) core.Field {
	field, _ := target.Fields.GetByName(core.FieldNameId).(*core.TextField)
	if field == nil {
		p.errorAt(def.Loc, "Invalid id field.")
		return nil
	}

	if directive != nil {
		for _, arg := range directive.Arguments {
			if !slices.Contains([]string{"name", "min", "max", "pattern", "autogeneratePattern"}, arg.Name.Value) {
				p.errorAt(arg.Loc, "The @field argument %q is not supported for the id field.", arg.Name.Value)
			}
		}
		for _, name := range []string{"min", "max", "pattern", "autogeneratePattern"} {
			if _, ok := args[name]; ok {
				field.Min = int(graphqlSDLArgInt(args, "min"))
				field.Max = int(graphqlSDLArgInt(args, "max"))
				field.Pattern = graphqlSDLArgString(args, "pattern")
				field.AutogeneratePattern = graphqlSDLArgString(args, "autogeneratePattern")
				break
			}
		}
	}

	return field
}

// -------------------------------------------------------------------
// Plan
// -------------------------------------------------------------------

func graphqlSDLFieldJSON(f core.Field) string {
	raw, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(raw)
}

func graphqlSDLRuleEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func graphqlSDLDiff(old *core.Collection, target *core.Collection) graphqlSchemaChange {
	change := graphqlSchemaChange{Collection: target.Name, Action: "update", Fields: []graphqlSchemaFieldChange{}, Details: []string{}}

	if !graphqlSDLRuleEqual(old.ListRule, target.ListRule) ||
		!graphqlSDLRuleEqual(old.ViewRule, target.ViewRule) ||
		!graphqlSDLRuleEqual(old.CreateRule, target.CreateRule) ||
		!graphqlSDLRuleEqual(old.UpdateRule, target.UpdateRule) ||
		!graphqlSDLRuleEqual(old.DeleteRule, target.DeleteRule) ||
		!graphqlSDLRuleEqual(old.AuthRule, target.AuthRule) ||
		!graphqlSDLRuleEqual(old.ManageRule, target.ManageRule) {
		change.Details = append(change.Details, "rules")
	}

	if !slices.Equal(old.Indexes, target.Indexes) {
		change.Details = append(change.Details, "indexes")
	}

	for _, f := range target.Fields {
		existing := old.Fields.GetByName(f.GetName())
		switch {
		case existing == nil:
			change.Fields = append(change.Fields, graphqlSchemaFieldChange{Name: f.GetName(), Action: "add", Type: f.Type()})
		case existing.Type() != f.Type():
			change.Destructive = true
			change.Fields = append(change.Fields, graphqlSchemaFieldChange{Name: f.GetName(), Action: "update", Type: f.Type(), Destructive: true})
		case graphqlSDLFieldJSON(existing) != graphqlSDLFieldJSON(f):
			change.Fields = append(change.Fields, graphqlSchemaFieldChange{Name: f.GetName(), Action: "update", Type: f.Type()})
		}
	}

	for _, f := range old.Fields {
		if target.Fields.GetByName(f.GetName()) == nil {
			change.Destructive = true
			change.Fields = append(change.Fields, graphqlSchemaFieldChange{Name: f.GetName(), Action: "remove", Type: f.Type(), Destructive: true})
		}
	}

	return change
}

// graphqlSchemaStateHash returns the hash of the current non-system collections (changes on any collection save).
func graphqlSchemaStateHash(app core.App, schema string) (string, error) {
	collections, err := app.FindAllCollections()
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(schema))
	h.Write([]byte{0})
	for _, c := range collections {
		if c.System {
			continue
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return "", err
		}
		h.Write(raw)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func newGraphQLSchemaPlan(app core.App, schema string) (*graphqlSchemaPlan, error) {
	plan := &graphqlSchemaPlan{
		Changes:  []graphqlSchemaChange{},
		Warnings: []string{},
		Errors:   []graphqlSchemaError{},
		CanApply: graphqlSchemaCanApply(app),
	}

	targets, remove, parseErrors, warnings := graphqlParseSchema(app, schema)
	if len(parseErrors) > 0 {
		plan.Errors = parseErrors
		return plan, nil
	}
	plan.Warnings = append(plan.Warnings, warnings...)

	for _, target := range targets {
		old, err := app.FindCollectionByNameOrId(target.Id)
		if err != nil {
			plan.Changes = append(plan.Changes, graphqlSchemaChange{
				Collection: target.Name,
				Action:     "create",
				Fields:     graphqlSDLAllFields(target, "add", false),
				Details:    []string{},
			})
			plan.upsert = append(plan.upsert, target)
			continue
		}

		change := graphqlSDLDiff(old, target)
		if len(change.Fields) > 0 || len(change.Details) > 0 {
			plan.Changes = append(plan.Changes, change)
			plan.upsert = append(plan.upsert, target)
		}
	}

	for _, c := range remove {
		plan.Changes = append(plan.Changes, graphqlSchemaChange{
			Collection:  c.Name,
			Action:      "delete",
			Fields:      graphqlSDLAllFields(c, "remove", true),
			Details:     []string{},
			Destructive: true,
		})
		plan.remove = append(plan.remove, c)
	}

	hash, err := graphqlSchemaStateHash(app, schema)
	if err != nil {
		return nil, err
	}
	plan.PlanHash = hash

	return plan, nil
}

func graphqlSDLAllFields(c *core.Collection, action string, destructive bool) []graphqlSchemaFieldChange {
	result := make([]graphqlSchemaFieldChange, 0, len(c.Fields))
	for _, f := range c.Fields {
		result = append(result, graphqlSchemaFieldChange{Name: f.GetName(), Action: action, Type: f.Type(), Destructive: destructive})
	}
	return result
}
