package apis_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/filesystem"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// -------------------------------------------------------------------
// Helpers (shared with the graphql tests)
// -------------------------------------------------------------------

// gqlDo sends a GraphQL POST request and returns the status and the decoded response.
func gqlDo(t testing.TB, mux *oauth2TestMux, headers map[string]string, query string, variables map[string]any) (int, map[string]any) {
	t.Helper()

	body, _ := json.Marshal(map[string]any{"query": query, "variables": variables})

	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}

	res := mux.do(http.MethodPost, "/api/graphql", strings.NewReader(string(body)), h)
	defer res.Body.Close()

	result := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&result)

	return res.StatusCode, result
}

// restDo sends a GET request and returns the status and the decoded response.
func restDo(t testing.TB, mux *oauth2TestMux, headers map[string]string, rawURL string) (int, map[string]any) {
	t.Helper()

	res := mux.do(http.MethodGet, rawURL, nil, headers)
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)

	result := map[string]any{}
	_ = json.Unmarshal(raw, &result)

	return res.StatusCode, result
}

func gqlGlobalId(collectionName, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(collectionName + ":" + id))
}

func gqlRawId(t testing.TB, globalId any) string {
	t.Helper()

	str, _ := globalId.(string)

	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		t.Fatalf("Invalid global id %v", globalId)
	}

	_, id, _ := strings.Cut(string(decoded), ":")

	return id
}

// gqlErrors returns the response errors (nil if none).
func gqlErrors(result map[string]any) []map[string]any {
	raw, _ := result["errors"].([]any)

	errs := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		m, _ := e.(map[string]any)
		errs = append(errs, m)
	}

	if len(errs) == 0 {
		return nil
	}

	return errs
}

func gqlErrorStatus(err map[string]any) int {
	ext, _ := err["extensions"].(map[string]any)
	status, _ := ext["status"].(float64)
	return int(status)
}

// gqlFixtures creates the GraphQL test collections and records:
//   - gql_categories: public list/view (name)
//   - gql_products: list = published or users, view = published or any auth
//     (all field types, unique handle, hidden "internal", self relation, protected files)
//   - gql_private: staff only list, view = any auth
//
// and changes the users List rule to "verified = true || id = @request.auth.id".
func gqlFixtures(t testing.TB, app core.App) {
	t.Helper()

	categories := core.NewBaseCollection("gql_categories")
	categories.ListRule = types.Pointer("")
	categories.ViewRule = types.Pointer("")
	categories.Fields.Add(
		&core.TextField{Name: "name"},
		&core.AutodateField{Name: "created", OnCreate: true},
	)
	if err := app.Save(categories); err != nil {
		t.Fatal(err)
	}

	products := core.NewBaseCollection("gql_products")
	products.ListRule = types.Pointer(`published = true || @request.auth.collectionName = "users"`)
	products.ViewRule = types.Pointer(`published = true || @request.auth.id != ""`)
	products.Fields.Add(
		&core.TextField{Name: "title"},
		&core.TextField{Name: "handle"},
		&core.NumberField{Name: "price"},
		&core.BoolField{Name: "published"},
		&core.SelectField{Name: "tags", Values: []string{"a", "b", "c"}, MaxSelect: 3},
		&core.JSONField{Name: "meta"},
		&core.GeoPointField{Name: "location"},
		&core.FileField{Name: "image", MaxSelect: 1, MaxSize: 1000},
		&core.FileField{Name: "docs", MaxSelect: 3, MaxSize: 1000, Protected: true},
		&core.RelationField{Name: "category", CollectionId: categories.Id, MaxSelect: 1},
		&core.TextField{Name: "internal", Hidden: true},
		&core.DateField{Name: "released"},
		&core.AutodateField{Name: "created", OnCreate: true},
	)
	products.AddIndex("idx_gql_products_handle", true, "handle", "")
	if err := app.Save(products); err != nil {
		t.Fatal(err)
	}
	products.Fields.Add(&core.RelationField{Name: "related", CollectionId: products.Id, MaxSelect: 3})
	if err := app.Save(products); err != nil {
		t.Fatal(err)
	}

	private := core.NewBaseCollection("gql_private")
	private.ViewRule = types.Pointer(`@request.auth.id != ""`)
	private.Fields.Add(
		&core.TextField{Name: "title"},
		&core.AutodateField{Name: "created", OnCreate: true},
	)
	if err := app.Save(private); err != nil {
		t.Fatal(err)
	}

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.ListRule = types.Pointer(`verified = true || id = @request.auth.id`)
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	categoryIds := []string{}
	for _, name := range []string{"shoes", "hats", "bags"} {
		r := core.NewRecord(categories)
		r.Set("name", name)
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		categoryIds = append(categoryIds, r.Id)
	}

	productIds := []string{}
	for i := range 6 {
		r := core.NewRecord(products)
		r.Set("title", fmt.Sprintf("Product %d", i))
		r.Set("handle", fmt.Sprintf("product-%d", i))
		r.Set("price", float64(i)*10.5)
		r.Set("published", i%2 == 0)
		r.Set("tags", []string{"a", "b", "c"}[:i%3+1])
		r.Set("meta", map[string]any{"i": i, "nested": []any{"x", i}})
		r.Set("location", types.GeoPoint{Lon: float64(i), Lat: float64(i) / 2})
		r.Set("category", categoryIds[i%3])
		r.Set("internal", "secret")
		if i%2 == 0 {
			r.Set("released", "2024-01-0"+fmt.Sprint(i+1)+" 10:00:00.123Z")
		}
		if i < 3 {
			f1, _ := filesystem.NewFileFromBytes([]byte("test"), "image.txt")
			f2, _ := filesystem.NewFileFromBytes([]byte("test"), "doc.txt")
			r.Set("image", f1)
			r.Set("docs", []any{f2})
		}
		if len(productIds) > 0 {
			// incl. relations to unpublished products
			r.Set("related", productIds[max(0, len(productIds)-2):])
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		productIds = append(productIds, r.Id)
	}

	for _, title := range []string{"p1", "p2"} {
		r := core.NewRecord(private)
		r.Set("title", title)
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
	}
}

// gqlActors returns the parity test actors headers.
func gqlActors(t *testing.T, app *tests.TestApp) map[string]map[string]string {
	t.Helper()

	products, _ := app.FindCollectionByNameOrId("gql_products")
	categories, _ := app.FindCollectionByNameOrId("gql_categories")
	users, _ := app.FindCollectionByNameOrId("users")

	customer, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	customerToken, err := tests.NewSessionAuthToken(app, customer)
	if err != nil {
		t.Fatal(err)
	}

	_, publicKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}

	_, ceilingKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, core.Permissions{
		Collections: map[string][]string{products.Id: {core.PermissionActionList}},
	})
	if err != nil {
		t.Fatal(err)
	}

	limitedRole, err := tests.CreateRole(app, "gql limited", core.Permissions{
		Collections: map[string][]string{products.Id: {core.PermissionActionList, core.PermissionActionView}},
	})
	if err != nil {
		t.Fatal(err)
	}
	limitedStaff, err := tests.CreateStaff(app, "gql_limited@example.com", limitedRole.Id)
	if err != nil {
		t.Fatal(err)
	}
	limitedToken, err := tests.NewSessionAuthToken(app, limitedStaff)
	if err != nil {
		t.Fatal(err)
	}

	installed := appInstall(t, app, "gql-app", core.Permissions{
		Collections: map[string][]string{
			products.Id:   {core.PermissionActionList, core.PermissionActionView},
			categories.Id: {core.PermissionActionView},
			users.Id:      {core.PermissionActionList},
		},
	})
	applicationToken := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

	online := extInstall(t, app, "gql-ext", core.Permissions{
		Collections: map[string][]string{
			products.Id:   {core.PermissionActionList, core.PermissionActionView},
			categories.Id: {core.PermissionActionList, core.PermissionActionView},
		},
	})
	extCreateStaff(t, app, "gql_online@example.com", core.Permissions{
		Collections: map[string][]string{
			products.Id: {core.PermissionActionList, core.PermissionActionView},
			users.Id:    {core.PermissionActionList, core.PermissionActionView},
		},
		System: map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead},
	})
	onlineToken, _ := extOnlineToken(t, app, online, "gql_online@example.com")

	return map[string]map[string]string{
		"guest+public key":       {"X-PB-Public-Key": publicKey},
		"customer":               {"Authorization": customerToken},
		"third-party token":      {"Authorization": rbacThirdPartyToken(t, app, "read_gql_products", "read_users")},
		"staff limited":          {"Authorization": limitedToken},
		"owner":                  {"Authorization": mustOwnerToken(t, app)},
		"application":            {"Authorization": applicationToken},
		"online token":           {"Authorization": onlineToken},
		"api key ceiling":        {"X-PB-Public-Key": ceilingKey},
		"api key ceiling+bearer": {"X-PB-Public-Key": ceilingKey, "Authorization": customerToken},
	}
}

type gqlParityField struct {
	gql  string // GraphQL field name
	rest string // REST record field name
	kind string // plain, date, file, files, rel, rels, geo
	sub  string // relation subselection
}

type gqlParityCollection struct {
	name     string
	singular string
	plural   string
	expand   string
	fields   []gqlParityField
}

var gqlParityCollections = []gqlParityCollection{
	{
		name: "gql_products", singular: "gqlProduct", plural: "gqlProducts", expand: "category,related",
		fields: []gqlParityField{
			{gql: "title", rest: "title", kind: "plain"},
			{gql: "handle", rest: "handle", kind: "plain"},
			{gql: "price", rest: "price", kind: "plain"},
			{gql: "published", rest: "published", kind: "plain"},
			{gql: "tags", rest: "tags", kind: "plain"},
			{gql: "meta", rest: "meta", kind: "plain"},
			{gql: "location", rest: "location", kind: "geo"},
			{gql: "image", rest: "image", kind: "file"},
			{gql: "docs", rest: "docs", kind: "files"},
			{gql: "category", rest: "category", kind: "rel", sub: "name"},
			{gql: "related", rest: "related", kind: "rels", sub: "title"},
			{gql: "released", rest: "released", kind: "date"},
			{gql: "created", rest: "created", kind: "date"},
		},
	},
	{
		name: "gql_categories", singular: "gqlCategory", plural: "gqlCategories",
		fields: []gqlParityField{
			{gql: "name", rest: "name", kind: "plain"},
			{gql: "created", rest: "created", kind: "date"},
		},
	},
	{
		name: "gql_private", singular: "gqlPrivate", plural: "gqlPrivates",
		fields: []gqlParityField{
			{gql: "title", rest: "title", kind: "plain"},
		},
	},
	{
		name: "users", singular: "user", plural: "users", expand: "rel",
		fields: []gqlParityField{
			{gql: "email", rest: "email", kind: "plain"},
			{gql: "emailVisibility", rest: "emailVisibility", kind: "plain"},
			{gql: "verified", rest: "verified", kind: "plain"},
			{gql: "username", rest: "username", kind: "plain"},
			{gql: "name", rest: "name", kind: "plain"},
			{gql: "avatar", rest: "avatar", kind: "file"},
			{gql: "rel", rest: "rel", kind: "rel", sub: "title"},
			{gql: "created", rest: "created", kind: "date"},
		},
	},
}

func (c gqlParityCollection) selection() string {
	parts := []string{"id"}
	for _, f := range c.fields {
		switch f.kind {
		case "geo":
			parts = append(parts, f.gql+" { lon lat }")
		case "file", "files":
			parts = append(parts, f.gql+" { filename }")
		case "rel", "rels":
			parts = append(parts, f.gql+" { id "+f.sub+" }")
		default:
			parts = append(parts, f.gql)
		}
	}
	return strings.Join(parts, " ")
}

// expectedFromREST converts a REST record JSON into the expected GraphQL node value.
func (c gqlParityCollection) expectedFromREST(t testing.TB, item map[string]any) map[string]any {
	t.Helper()

	expand, _ := item["expand"].(map[string]any)

	result := map[string]any{"id": gqlGlobalId(c.name, item["id"].(string))}

	for _, f := range c.fields {
		v, ok := item[f.rest]
		if !ok {
			result[f.gql] = nil
			if f.kind == "rels" {
				result[f.gql] = []any{}
			}
			continue
		}

		switch f.kind {
		case "date":
			s, _ := v.(string)
			if s == "" {
				result[f.gql] = nil
				continue
			}
			dt, err := types.ParseDateTime(s)
			if err != nil {
				t.Fatal(err)
			}
			result[f.gql] = dt.Time().UTC().Format(time.RFC3339Nano)
		case "file":
			if s, _ := v.(string); s == "" {
				result[f.gql] = nil
			} else {
				result[f.gql] = map[string]any{"filename": s}
			}
		case "files":
			list := []any{}
			for _, name := range v.([]any) {
				list = append(list, map[string]any{"filename": name})
			}
			result[f.gql] = list
		case "rel":
			rel, _ := expand[f.rest].(map[string]any)
			if rel == nil {
				result[f.gql] = nil
			} else {
				relCollection, _ := rel["collectionName"].(string)
				result[f.gql] = map[string]any{"id": gqlGlobalId(relCollection, rel["id"].(string)), f.sub: rel[f.sub]}
			}
		case "rels":
			list := []any{}
			rels, _ := expand[f.rest].([]any)
			for _, raw := range rels {
				rel := raw.(map[string]any)
				relCollection, _ := rel["collectionName"].(string)
				list = append(list, map[string]any{"id": gqlGlobalId(relCollection, rel["id"].(string)), f.sub: rel[f.sub]})
			}
			result[f.gql] = list
		default:
			result[f.gql] = v
		}
	}

	return result
}

func gqlNormalize(v any) any {
	raw, _ := json.Marshal(v)
	var result any
	_ = json.Unmarshal(raw, &result)
	return result
}

// -------------------------------------------------------------------
// REST/GraphQL parity
// -------------------------------------------------------------------

// TestRecordReadParity checks that the REST records list/view (+ expand) and the GraphQL
// connections/singular queries (+ relations) return the same records and field values
// for every actor kind (G-I1: a single records read path).
func TestRecordReadParity(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	gqlFixtures(t, app)

	actors := gqlActors(t, app)
	mux := oauth2Mux(t, app)

	var total int

	for actorName, headers := range actors {
		for _, c := range gqlParityCollections {
			t.Run(actorName+"/"+c.name+"/list", func(t *testing.T) {
				total++

				restURL := "/api/collections/" + c.name + "/records?perPage=500&sort=created,id"
				if c.expand != "" {
					restURL += "&expand=" + url.QueryEscape(c.expand)
				}
				restStatus, restResult := restDo(t, mux, headers, restURL)

				status, result := gqlDo(t, mux, headers, "{ "+c.plural+"(first: 100) { totalCount nodes { "+c.selection()+" } } }", nil)
				if status != 200 {
					t.Fatalf("Expected GraphQL status 200, got %d (%v)", status, result)
				}

				errs := gqlErrors(result)

				if restStatus != 200 {
					if len(errs) != 1 || gqlErrorStatus(errs[0]) != restStatus {
						t.Fatalf("Expected a GraphQL error with status %d, got %v", restStatus, result)
					}
					if data, _ := result["data"].(map[string]any); data == nil || data[c.plural] != nil {
						t.Fatalf("Expected null %s, got %v", c.plural, result["data"])
					}
					return
				}

				if errs != nil {
					t.Fatalf("Unexpected GraphQL errors %v (REST %v)", errs, restResult)
				}

				conn := result["data"].(map[string]any)[c.plural].(map[string]any)

				expected := []any{}
				for _, item := range restResult["items"].([]any) {
					expected = append(expected, c.expectedFromREST(t, item.(map[string]any)))
				}

				if !reflect.DeepEqual(gqlNormalize(expected), gqlNormalize(conn["nodes"])) {
					e, _ := json.Marshal(expected)
					g, _ := json.Marshal(conn["nodes"])
					t.Fatalf("REST/GraphQL list mismatch\nREST:    %s\nGraphQL: %s", e, g)
				}

				if conn["totalCount"] != restResult["totalItems"] {
					t.Fatalf("Expected totalCount %v, got %v", restResult["totalItems"], conn["totalCount"])
				}
			})

			records, err := app.FindAllRecords(c.name)
			if err != nil {
				t.Fatal(err)
			}

			for _, record := range records {
				t.Run(actorName+"/"+c.name+"/view/"+record.Id, func(t *testing.T) {
					total++

					restURL := "/api/collections/" + c.name + "/records/" + record.Id
					if c.expand != "" {
						restURL += "?expand=" + url.QueryEscape(c.expand)
					}
					restStatus, restResult := restDo(t, mux, headers, restURL)

					status, result := gqlDo(t, mux, headers, `query ($id: ID!) { item: `+c.singular+`(id: $id) { `+c.selection()+` } }`, map[string]any{
						"id": gqlGlobalId(c.name, record.Id),
					})
					if status != 200 {
						t.Fatalf("Expected GraphQL status 200, got %d (%v)", status, result)
					}

					errs := gqlErrors(result)
					data, _ := result["data"].(map[string]any)

					switch restStatus {
					case 200:
						if errs != nil {
							t.Fatalf("Unexpected GraphQL errors %v", errs)
						}

						expected := c.expectedFromREST(t, restResult)
						if !reflect.DeepEqual(gqlNormalize(expected), gqlNormalize(data["item"])) {
							e, _ := json.Marshal(expected)
							g, _ := json.Marshal(data["item"])
							t.Fatalf("REST/GraphQL view mismatch\nREST:    %s\nGraphQL: %s", e, g)
						}
					case 404:
						if errs != nil || data == nil || data["item"] != nil {
							t.Fatalf("Expected null item without errors, got %v", result)
						}
					default:
						if len(errs) != 1 || gqlErrorStatus(errs[0]) != restStatus {
							t.Fatalf("Expected a GraphQL error with status %d, got %v", restStatus, result)
						}
					}
				})
			}
		}
	}

	t.Logf("REST/GraphQL parity subtests: %d", total)
}
