package apis_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestOAuth2ClientAPIKeysApi(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")
	storefront := oauth2StubClient(t, app, "users", "storefront")
	firstParty := oauth2StubClient(t, app, "users", "first_party", func(c *core.OAuth2Client) { c.SetFirstParty(true) })
	dashboard, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil {
		t.Fatal(err)
	}

	readRole, err := tests.CreateRole(app, "clients read", core.Permissions{System: map[string]string{
		core.PermissionResourceOAuth2Clients: core.PermissionLevelRead,
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeRole, err := tests.CreateRole(app, "clients write", core.Permissions{System: map[string]string{
		core.PermissionResourceOAuth2Clients: core.PermissionLevelWrite,
	}})
	if err != nil {
		t.Fatal(err)
	}

	staffToken := func(email string, roles ...string) (string, *core.Record) {
		staff, err := tests.CreateStaff(app, email, roles...)
		if err != nil {
			t.Fatal(err)
		}
		token, err := tests.NewSessionAuthToken(app, staff)
		if err != nil {
			t.Fatal(err)
		}
		return token, staff
	}

	readToken, _ := staffToken("read@example.com", readRole.Id)
	writeToken, writeStaff := staffToken("write@example.com", writeRole.Id)
	noneToken, _ := staffToken("none@example.com")
	ownerToken := mustOwnerToken(t, app)
	customerToken := tests.AuthToken("users", "test@example.com")

	auth := func(token string) map[string]string {
		return map[string]string{"Authorization": token}
	}

	mux := newAPIKeyMux(t, app)

	base := "/api/oauth2/clients/" + storefront.Id + "/api-keys"
	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}
	demo2Read := `{"collections":{"` + demo2.Id + `":["list","view"]}}`

	// RBAC
	mux.expect("list guest", 401, http.MethodGet, base, "", nil)
	mux.expect("list customer", 403, http.MethodGet, base, "", auth(customerToken))
	mux.expect("list staff without roles", 403, http.MethodGet, base, "", auth(noneToken))
	mux.expect("list staff read", 200, http.MethodGet, base, "", auth(readToken), `[]`)
	mux.expect("create staff read", 403, http.MethodPost, base, `{"name":"x","kind":"public"}`, auth(readToken))
	mux.expect("create guest", 401, http.MethodPost, base, `{"name":"x","kind":"public"}`, nil)
	mux.expect("create missing client", 404, http.MethodPost, "/api/oauth2/clients/missing/api-keys", `{"name":"x","kind":"public"}`, auth(ownerToken))

	// the first-party clients (and the _superusers clients) are Owner only (same as the client secret)
	firstPartyBase := "/api/oauth2/clients/" + firstParty.Id + "/api-keys"
	mux.expect("create first-party staff write", 403, http.MethodPost, firstPartyBase, `{"name":"x","kind":"public"}`, auth(writeToken))
	mux.expect("create first-party Owner", 200, http.MethodPost, firstPartyBase, `{"name":"x","kind":"public"}`, auth(ownerToken))

	// validation
	mux.expect("create invalid kind", 400, http.MethodPost, base, `{"name":"x","kind":"secret"}`, auth(writeToken), `"kind"`)
	mux.expect("create missing name", 400, http.MethodPost, base, `{"kind":"public"}`, auth(writeToken), `"name"`)
	mux.expect("create private without buyer context mode", 400, http.MethodPost, base, `{"name":"x","kind":"private"}`, auth(writeToken), `"buyerContext"`)
	mux.expect("create system permissions", 400, http.MethodPost, base, `{"name":"x","kind":"public","permissions":{"system":{"logs":"read"}}}`, auth(writeToken), `"permissions"`)
	mux.expect("create dashboard client key", 400, http.MethodPost, "/api/oauth2/clients/"+dashboard.Id+"/api-keys", `{"name":"x","kind":"public"}`, auth(ownerToken), `"clientRef"`)
	mux.expect("create private with origins", 400, http.MethodPost, base, `{"name":"x","kind":"private","buyerContext":"none","allowedOrigins":["https://shop.example.com"]}`, auth(writeToken), `"allowedOrigins"`)

	// create public
	body := mux.expect("create public", 200, http.MethodPost, base,
		`{"name":"Storefront","kind":"public","allowedOrigins":["https://Shop.example.com"],"permissions":`+demo2Read+`}`,
		auth(writeToken), `"kind":"public"`, `"allowedOrigins":["https://shop.example.com"]`, `"createdBy":"`+writeStaff.Id+`"`)
	var public struct {
		APIKey struct {
			Id          string `json:"id"`
			Token       string `json:"token"`
			TokenPrefix string `json:"tokenPrefix"`
		} `json:"apiKey"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &public); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(public.Token, core.APIKeyPublicTokenPrefix) || public.APIKey.Token != public.Token || public.APIKey.TokenPrefix != public.Token[:10] {
		t.Fatalf("Invalid public key response %s", body)
	}

	// create private (the plain token is returned only once)
	body = mux.expect("create private", 200, http.MethodPost, base,
		`{"name":"Server","kind":"private","buyerContext":"required","permissions":`+demo2Read+`}`,
		auth(writeToken), `"kind":"private"`, `"buyerContext":"required"`)
	var private struct {
		APIKey struct {
			Id    string `json:"id"`
			Token string `json:"token"`
		} `json:"apiKey"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &private); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(private.Token, core.APIKeyPrivateTokenPrefix) || private.APIKey.Token != "" {
		t.Fatalf("Invalid private key response %s", body)
	}

	// list (never the private token or the hashes)
	listBody := mux.expect("list staff read after create", 200, http.MethodGet, base, "", auth(readToken), public.Token, private.APIKey.Id)
	for _, secret := range []string{private.Token, "tokenHash", "token_hash"} {
		if strings.Contains(listBody, secret) {
			t.Fatalf("Expected %q to not be listed, got %s", secret, listBody)
		}
	}

	// the keys work
	data := `/api/collections/demo2/records`
	mux.expect("public key works", 200, http.MethodGet, data, "", map[string]string{apis.APIKeyPublicHeader: public.Token, "Origin": "https://shop.example.com"})
	mux.expect("private key works", 200, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: private.Token, apis.APIKeyBuyerIPHeader: "203.0.113.9"})

	// update (disable/enable + permissions)
	keyURL := base + "/" + private.APIKey.Id
	mux.expect("update staff read", 403, http.MethodPatch, keyURL, `{"disabled":true}`, auth(readToken))
	mux.expect("update other client path", 404, http.MethodPatch, "/api/oauth2/clients/"+firstParty.Id+"/api-keys/"+private.APIKey.Id, `{"disabled":true}`, auth(ownerToken))
	mux.expect("disable", 200, http.MethodPatch, keyURL, `{"disabled":true}`, auth(writeToken), `"disabled":true`)
	mux.expect("disabled key", 401, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: private.Token, apis.APIKeyBuyerIPHeader: "203.0.113.9"})
	mux.expect("enable", 200, http.MethodPatch, keyURL, `{"disabled":false}`, auth(writeToken), `"disabled":false`)
	mux.expect("enabled key", 200, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: private.Token, apis.APIKeyBuyerIPHeader: "203.0.113.9"})
	mux.expect("update permissions", 200, http.MethodPatch, keyURL, `{"permissions":{"collections":{}}}`, auth(writeToken), `"permissions":{`)
	mux.expect("narrowed key", 403, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: private.Token, apis.APIKeyBuyerIPHeader: "203.0.113.9"})
	mux.expect("update invalid permissions", 400, http.MethodPatch, keyURL, `{"permissions":{"system":{"sql":"write"}}}`, auth(writeToken), `"permissions"`)
	mux.expect("update origins of a private key", 400, http.MethodPatch, keyURL, `{"allowedOrigins":["https://a.example.com"]}`, auth(writeToken), `"allowedOrigins"`)

	// rotate (the old token stops working immediately)
	mux.expect("rotate staff read", 403, http.MethodPost, keyURL+"/rotate-secret", "", auth(readToken))
	body = mux.expect("rotate", 200, http.MethodPost, keyURL+"/rotate-secret", "", auth(writeToken))
	var rotated struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &rotated); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotated.Token, core.APIKeyPrivateTokenPrefix) || rotated.Token == private.Token {
		t.Fatalf("Invalid rotated token %s", body)
	}
	mux.expect("rotated old token", 401, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: private.Token, apis.APIKeyBuyerIPHeader: "203.0.113.9"})

	// delete
	mux.expect("delete staff read", 403, http.MethodDelete, keyURL, "", auth(readToken))
	mux.expect("delete", 204, http.MethodDelete, keyURL, "", auth(writeToken))
	mux.expect("delete again", 404, http.MethodDelete, keyURL, "", auth(writeToken))
	mux.expect("deleted key", 401, http.MethodGet, data, "", map[string]string{apis.APIKeyPrivateHeader: rotated.Token})
}

func TestAPIKeysRecordsApi(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")
	storefront := oauth2StubClient(t, app, "users", "storefront")

	key, _, err := tests.NewClientAPIKey(app, storefront, core.APIKeyKindPrivate, core.Permissions{})
	if err != nil {
		t.Fatal(err)
	}

	writeRole, err := tests.CreateRole(app, "clients write", core.Permissions{System: map[string]string{
		core.PermissionResourceOAuth2Clients: core.PermissionLevelWrite,
	}})
	if err != nil {
		t.Fatal(err)
	}
	staff, err := tests.CreateStaff(app, "write@example.com", writeRole.Id)
	if err != nil {
		t.Fatal(err)
	}
	staffToken, err := tests.NewSessionAuthToken(app, staff)
	if err != nil {
		t.Fatal(err)
	}
	ownerToken := mustOwnerToken(t, app)

	mux := newAPIKeyMux(t, app)

	records := "/api/collections/" + core.CollectionNameAPIKeys + "/records"

	for name, token := range map[string]string{"Owner": ownerToken, "staff": staffToken} {
		body := mux.expect(name+" list", 200, http.MethodGet, records, "", map[string]string{"Authorization": token}, key.Id)
		if strings.Contains(body, "tokenHash") || strings.Contains(body, key.TokenHash()) {
			t.Fatalf("[%s] Expected the token hash to be hidden, got %s", name, body)
		}

		body = mux.expect(name+" view", 200, http.MethodGet, records+"/"+key.Id, "", map[string]string{"Authorization": token}, key.Id)
		if strings.Contains(body, "tokenHash") || strings.Contains(body, key.TokenHash()) {
			t.Fatalf("[%s] Expected the token hash to be hidden, got %s", name, body)
		}
	}

	// the keys are created and changed only through the dedicated endpoints (the records API is Owner only)
	create := `{"name":"x","clientRef":"` + storefront.Id + `","kind":"private","buyerContext":"none"}`
	mux.expect("staff create", 403, http.MethodPost, records, create, map[string]string{"Authorization": staffToken})
	mux.expect("staff update", 403, http.MethodPatch, records+"/"+key.Id, `{"disabled":true}`, map[string]string{"Authorization": staffToken})
	mux.expect("Owner create", 200, http.MethodPost, records, create, map[string]string{"Authorization": ownerToken}, `"kind":"private"`)

	// a key never reaches its own collection
	_, allKey, err := tests.NewClientAPIKey(app, storefront, core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	mux.expect("key list", 403, http.MethodGet, records, "", map[string]string{apis.APIKeyPublicHeader: allKey})

	mux.expect("staff delete", 204, http.MethodDelete, records+"/"+key.Id, "", map[string]string{"Authorization": staffToken})
}
