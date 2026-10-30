package migratecmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/pocketbase/dbx"
)

// automigrateOnGraphQLSchemaApply writes the single migration of an applied
// dashboard GraphQL schema (marked as applied, like the other automigrations).
func (p *plugin) automigrateOnGraphQLSchemaApply(e *core.GraphQLSchemaApplyRequestEvent) error {
	if err := e.Next(); err != nil {
		return err
	}

	if len(e.Changes) == 0 {
		return nil
	}

	var template string
	var err error
	if p.config.TemplateLang == TemplateLangJS {
		template, err = p.jsGraphQLSchemaTemplate(e.Changes)
	} else {
		template, err = p.goGraphQLSchemaTemplate(e.Changes)
	}
	if err != nil {
		return fmt.Errorf("failed to resolve the graphql schema template: %w", err)
	}

	if err := os.MkdirAll(p.config.Dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create migration dir: %w", err)
	}

	// note: 2 applies could happen within the same second
	var name string
	for ts := time.Now().Unix(); ; ts++ {
		name = fmt.Sprintf("%d_graphql_schema.%s", ts, p.config.TemplateLang)
		if _, err := os.Stat(filepath.Join(p.config.Dir, name)); errors.Is(err, os.ErrNotExist) {
			break
		}
	}

	_, err = e.App.DB().Insert(core.DefaultMigrationsTable, dbx.Params{
		"file":    name,
		"applied": time.Now().UnixMicro(),
	}).Execute()
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(p.config.Dir, name), []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to save the migration file: %w", err)
	}

	e.MigrationFile = name

	return nil
}

// graphqlSchemaChangeGroups splits the changes (the secrets aren't part of the migrations, like in automigrate).
func graphqlSchemaChangeGroups(changes []core.GraphQLSchemaCollectionChange) (created, updated, deleted []core.GraphQLSchemaCollectionChange) {
	strip := func(c *core.Collection) {
		if c != nil && c.IsAuth() {
			c.OAuth2.Providers = nil
			c.OAuth2Server.SigningKeys = nil
		}
	}

	for _, change := range changes {
		strip(change.Old)
		strip(change.New)

		switch {
		case change.Old == nil:
			created = append(created, change)
		case change.New == nil:
			deleted = append(deleted, change)
		default:
			updated = append(updated, change)
		}
	}

	return created, updated, deleted
}

func graphqlSchemaSnapshot(items []core.GraphQLSchemaCollectionChange, indent string, unit string, useOld bool) (string, error) {
	data := make([]map[string]any, len(items))
	for i, item := range items {
		c := item.New
		if useOld {
			c = item.Old
		}

		raw, err := toMap(c)
		if err != nil {
			return "", err
		}
		delete(raw, "created")
		delete(raw, "updated")
		deleteNestedMapKey(raw, "oauth2", "providers")
		deleteNestedMapKey(raw, "oauth2Server", "signingKeys")
		data[i] = raw
	}

	result, err := marhshalWithoutEscape(data, indent, unit)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func (p *plugin) jsGraphQLSchemaTemplate(changes []core.GraphQLSchemaCollectionChange) (string, error) {
	created, updated, deleted := graphqlSchemaChangeGroups(changes)

	var up, down strings.Builder

	if len(created) > 0 {
		snapshot, err := graphqlSchemaSnapshot(created, "  ", "  ", false)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&up, "  app.importCollections(%s, false);\n\n", snapshot)
	}

	if len(deleted) > 0 {
		snapshot, err := graphqlSchemaSnapshot(deleted, "  ", "  ", true)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&down, "  app.importCollections(%s, false);\n\n", snapshot)
	}

	for _, change := range updated {
		upParts, downParts, err := p.jsDiffParts(change.New, change.Old)
		if errors.Is(err, ErrEmptyTemplate) {
			continue
		}
		if err != nil {
			return "", err
		}

		fmt.Fprintf(&up, "  {\n  const collection = app.findCollectionByNameOrId(%q)\n\n  %s\n\n  app.save(collection)\n  }\n\n", change.New.Id, upParts)
		fmt.Fprintf(&down, "  {\n  const collection = app.findCollectionByNameOrId(%q)\n\n  %s\n\n  app.save(collection)\n  }\n\n", change.Old.Id, downParts)
	}

	remove := func(out *strings.Builder, id string) {
		fmt.Fprintf(out, "  {\n  const collection = app.findCollectionByNameOrId(%q)\n  collection.integrityChecks(false)\n  app.delete(collection)\n  }\n\n", id)
	}
	for _, change := range deleted {
		remove(&up, change.Old.Id)
	}
	for _, change := range created {
		remove(&down, change.New.Id)
	}

	return jsTypesDirective + "migrate((app) => {\n" + up.String() + "}, (app) => {\n" + down.String() + "})\n", nil
}

func (p *plugin) goGraphQLSchemaTemplate(changes []core.GraphQLSchemaCollectionChange) (string, error) {
	created, updated, deleted := graphqlSchemaChangeGroups(changes)

	var up, down strings.Builder

	imported := func(out *strings.Builder, snapshot string) {
		fmt.Fprintf(out, "\t\tif err := app.ImportCollectionsByMarshaledJSON([]byte(`%s`), false); err != nil {\n\t\t\treturn err\n\t\t}\n\n", escapeBacktick(snapshot))
	}

	if len(created) > 0 {
		snapshot, err := graphqlSchemaSnapshot(created, "\t\t", "\t", false)
		if err != nil {
			return "", err
		}
		imported(&up, snapshot)
	}

	if len(deleted) > 0 {
		snapshot, err := graphqlSchemaSnapshot(deleted, "\t\t", "\t", true)
		if err != nil {
			return "", err
		}
		imported(&down, snapshot)
	}

	block := func(out *strings.Builder, id string, parts string) {
		fmt.Fprintf(out, "\t\t{\n\t\tcollection, err := app.FindCollectionByNameOrId(%q)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\n\t\t%s\n\n\t\tif err := app.Save(collection); err != nil {\n\t\t\treturn err\n\t\t}\n\t\t}\n\n", id, parts)
	}

	for _, change := range updated {
		upParts, downParts, err := p.goDiffParts(change.New, change.Old)
		if errors.Is(err, ErrEmptyTemplate) {
			continue
		}
		if err != nil {
			return "", err
		}

		block(&up, change.New.Id, upParts)
		block(&down, change.Old.Id, downParts)
	}

	removeOne := func(out *strings.Builder, id string) {
		fmt.Fprintf(out, "\t\t{\n\t\tcollection, err := app.FindCollectionByNameOrId(%q)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\n\t\tcollection.IntegrityChecks(false)\n\t\tif err := app.Delete(collection); err != nil {\n\t\t\treturn err\n\t\t}\n\t\t}\n\n", id)
	}
	for _, change := range deleted {
		removeOne(&up, change.Old.Id)
	}
	for _, change := range created {
		removeOne(&down, change.New.Id)
	}

	combined := up.String() + down.String()

	imports := ""
	if strings.Contains(combined, "json.Unmarshal(") || strings.Contains(combined, "json.Marshal(") {
		imports = "\t\"encoding/json/v2\"\n\n"
	}

	const template = `package %s

import (
%s	"github.com/lumm2509/pocketbomb/core"
	m "github.com/lumm2509/pocketbomb/migrations"
)

func init() {
	m.Register(func(app core.App) error {
%s		return nil
	}, func(app core.App) error {
%s		return nil
	})
}
`

	return fmt.Sprintf(template, filepath.Base(p.config.Dir), imports, up.String(), down.String()), nil
}
