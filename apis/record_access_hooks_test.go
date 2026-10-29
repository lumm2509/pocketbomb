package apis_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

// rbacAuditSetup creates an "audit" staff member with a legacy role (saved without validation)
// that has all Owner-equivalent levels plus every other assignable write permission
// and returns the staff and Owner tokens.
func rbacAuditSetup(t testing.TB, app *tests.TestApp) (staffToken string, ownerToken string, staff *core.Record) {
	t.Helper()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	role := core.NewRole(app)
	role.SetName("audit")
	role.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System: map[string]string{
			// Owner-equivalent (legacy, never granted)
			"collections": "write",
			"settings":    "write",
			"backups":     "write",
			"sql":         "write",
			// assignable
			"logs":           "write",
			"crons":          "write",
			"webhooks":       "write",
			"llm":            "write",
			"oauth2_clients": "write",
			"roles":          "write",
			"staff":          "write",
			"sessions":       "write",
			"impersonate":    "write",
		},
	})
	if err := app.SaveNoValidate(role); err != nil {
		t.Fatal(err)
	}

	staff, err = tests.CreateStaff(app, "audit@example.com", role.Id)
	if err != nil {
		t.Fatal(err)
	}

	staffToken, err = tests.NewSessionAuthToken(app, staff)
	if err != nil {
		t.Fatal(err)
	}

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	ownerToken, err = tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	return staffToken, ownerToken, staff
}

func TestRBACOwnerEquivalencePaths(t *testing.T) {
	t.Parallel()

	type scenario struct {
		name   string
		method string
		url    func(app *tests.TestApp) string
		body   func(app *tests.TestApp) string
		// expected staff status (and optionally the Owner status, 0 = not checked)
		staffStatus int
		ownerStatus int
		staffNot    []string
		ownerHas    []string
	}

	static := func(s string) func(app *tests.TestApp) string {
		return func(app *tests.TestApp) string { return s }
	}

	superusersId := func(app *tests.TestApp) string {
		c, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
		return c.Id
	}

	usersId := func(app *tests.TestApp) string {
		c, _ := app.FindCollectionByNameOrId("users")
		return c.Id
	}

	scenarios := []scenario{
		// R1-F1
		{name: "collections write (create)", method: http.MethodPost, url: static("/api/collections"), body: static(`{"name":"audit_new","type":"base"}`), staffStatus: 403, ownerStatus: 200},
		{name: "collections write (dry-run view)", method: http.MethodPost, url: static("/api/collections/meta/dry-run-view"), body: static(`{"query":"select id, tokenKey from _superusers"}`), staffStatus: 403},
		{name: "collections write (update system collection)", method: http.MethodPatch, url: static("/api/collections/_superusers"), body: static(`{"listRule":""}`), staffStatus: 403},
		{name: "collections read stays assignable", method: http.MethodGet, url: static("/api/collections"), staffStatus: 200, staffNot: []string{`"privateKey":"`, `"secret":"`}},
		{name: "backups read", method: http.MethodGet, url: static("/api/backups"), staffStatus: 403, ownerStatus: 200},
		{name: "backups write", method: http.MethodPost, url: static("/api/backups"), body: static(`{"name":"audit.zip"}`), staffStatus: 403},
		{name: "sql", method: http.MethodPost, url: static("/api/sql"), body: static(`{"query":"select 1"}`), staffStatus: 403, ownerStatus: 200},
		{name: "signing key rotation (Owner only)", method: http.MethodPost, url: static("/api/oauth2/users/keys/rotate"), staffStatus: 403},
		// settings
		{name: "settings write (AppURL)", method: http.MethodPatch, url: static("/api/settings"), body: static(`{"meta":{"appURL":"https://evil.example.com"}}`), staffStatus: 403},
		{name: "settings read redacts the secrets", method: http.MethodGet, url: static("/api/settings"), staffStatus: 200, staffNot: []string{"smtp_secret_password"}},
		// staff read: tokenKey never exported/filterable for non-Owners
		{name: "staff read without tokenKey", method: http.MethodGet, url: static("/api/collections/_superusers/records"), staffStatus: 200, ownerStatus: 200, staffNot: []string{`"tokenKey"`, `"password"`}},
		{name: "tokenKey filter (oracle)", method: http.MethodGet, url: static("/api/collections/_superusers/records?filter=" + url.QueryEscape("tokenKey ~ 'a'")), staffStatus: 400, ownerStatus: 200},
		{name: "password filter (oracle)", method: http.MethodGet, url: static("/api/collections/_superusers/records?filter=" + url.QueryEscape("password ~ 'a'")), staffStatus: 400},
		{name: "@collection secret field filter (oracle)", method: http.MethodGet, url: static("/api/collections/demo2/records?filter=" + url.QueryEscape("@collection._superusers.tokenKey ~ 'a'")), staffStatus: 400},
		{name: "@collection join into a not permitted collection (oracle)", method: http.MethodGet, url: static("/api/collections/demo2/records?filter=" + url.QueryEscape("@collection.demo1.text ~ 'a'")), staffStatus: 400, ownerStatus: 200},
		// sessions: only list/view/delete
		{
			name: "sessions write cannot create OTPs (Owner takeover)", method: http.MethodPost, url: static("/api/collections/_otps/records"),
			body: func(app *tests.TestApp) string {
				return `{"collectionRef":"` + superusersId(app) + `","recordRef":"sywbhecnh46rhm0","password":"123456"}`
			},
			staffStatus: 403,
		},
		{
			name: "sessions write cannot link external auths", method: http.MethodPost, url: static("/api/collections/_externalAuths/records"),
			body: func(app *tests.TestApp) string {
				return `{"collectionRef":"` + usersId(app) + `","recordRef":"4q1xlclmfloku33","provider":"gitlab","providerId":"attacker"}`
			},
			staffStatus: 403,
		},
		// oauth2 clients
		{
			name: "_superusers client (Owner only)", method: http.MethodPost, url: static("/api/collections/_oauth2Clients/records"),
			body: func(app *tests.TestApp) string {
				return `{"name":"x","clientId":"audit_su","type":"public","collectionRef":"` + superusersId(app) + `","redirectURIs":["https://evil.example.com/cb"],"scopes":["openid"],"firstParty":true}`
			},
			staffStatus: 403,
		},
		{
			name: "first-party users client (consent bypass, Owner only)", method: http.MethodPost, url: static("/api/collections/_oauth2Clients/records"),
			body: func(app *tests.TestApp) string {
				return `{"name":"x","clientId":"audit_1p","type":"public","collectionRef":"` + usersId(app) + `","redirectURIs":["https://evil.example.com/cb"],"scopes":["openid"],"firstParty":true}`
			},
			staffStatus: 403,
		},
		{
			name: "third-party users client", method: http.MethodPost, url: static("/api/collections/_oauth2Clients/records"),
			body: func(app *tests.TestApp) string {
				return `{"name":"x","clientId":"audit_3p","type":"public","collectionRef":"` + usersId(app) + `","redirectURIs":["https://example.com/cb"],"scopes":["openid"],"firstParty":false}`
			},
			staffStatus: 200,
		},
		{name: "pb_dashboard secret (Owner only)", method: http.MethodPost, url: func(app *tests.TestApp) string {
			c, _ := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
			return "/api/oauth2/clients/" + c.Id + "/rotate-secret"
		}, staffStatus: 403},
		// webhooks
		{
			name: "webhook system collection topic (Owner only)", method: http.MethodPost, url: static("/api/collections/_webhooks/records"),
			body:        static(`{"name":"x","uri":"https://example.com/hook","topics":["_superusers.update"]}`),
			staffStatus: 403, ownerStatus: 200,
		},
		{
			// W1: the staff can't subscribe to the records it can't view (users)
			name: "webhook regular collection topic without view permission", method: http.MethodPost, url: static("/api/collections/_webhooks/records"),
			body:        static(`{"name":"x","uri":"https://example.com/hook","topics":["users.update"]}`),
			staffStatus: 400, ownerStatus: 200,
		},
		{
			name: "webhook regular collection topic with view permission", method: http.MethodPost, url: static("/api/collections/_webhooks/records"),
			body:        static(`{"name":"x","uri":"https://example.com/hook","topics":["demo2.update"]}`),
			staffStatus: 200,
			staffNot:    []string{`"secret":"`},
		},
	}

	for _, s := range scenarios {
		for _, asOwner := range []bool{false, true} {
			expected := s.staffStatus
			if asOwner {
				if s.ownerStatus == 0 {
					continue
				}
				expected = s.ownerStatus
			}

			name := s.name + " (staff)"
			if asOwner {
				name = s.name + " (Owner)"
			}

			t.Run(name, func(t *testing.T) {
				app, _ := tests.NewTestApp()
				defer app.Cleanup()

				app.Settings().SMTP.Password = "smtp_secret_password"

				staffToken, ownerToken, _ := rbacAuditSetup(t, app)

				token := staffToken
				if asOwner {
					token = ownerToken
				}

				body := ""
				if s.body != nil {
					body = s.body(app)
				}

				b := newOAuth2Browser(t, app)
				res, resBody := b.do(s.method, s.url(app), body, map[string]string{
					"Authorization": token,
					"Content-Type":  "application/json",
				})
				b.expectStatus(res, resBody, expected)

				if !asOwner {
					for _, v := range s.staffNot {
						if strings.Contains(resBody, v) {
							t.Fatalf("Expected %q to not be in the staff response %s", v, resBody)
						}
					}
				} else {
					for _, v := range s.ownerHas {
						if !strings.Contains(resBody, v) {
							t.Fatalf("Expected %q in the Owner response %s", v, resBody)
						}
					}
				}
			})
		}
	}
}

func TestRBACSessionsRevocationAndClientLinkedWebhookSecrets(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	staffToken, ownerToken, _ := rbacAuditSetup(t, app)

	// sessions write still allows revocation (delete)
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	session, err := tests.CreateAuthSession(app, user)
	if err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)
	res, body := b.do(http.MethodDelete, "/api/collections/_authSessions/records/"+session.Id, "", map[string]string{"Authorization": staffToken})
	b.expectStatus(res, body, http.StatusNoContent)

	// the secrets of the OAuth2 client linked subscriptions are Owner only
	oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
		c.OAuth2Server.Scopes = append(c.OAuth2Server.Scopes, "users:read")
	})
	client := oauth2StubClient(t, app, "users", "hooks_client", func(c *core.OAuth2Client) {
		c.SetScopes(append(c.Scopes(), "users:read"))
	})

	linked := core.NewWebhook(app)
	linked.SetName("linked")
	linked.SetURI("https://example.com/linked")
	linked.SetTopics([]string{"users.update"})
	linked.SetClient(client.Id)
	if err := app.Save(linked); err != nil {
		t.Fatal(err)
	}

	// note: the staff can view demo2 (W1: the subscription topics must be viewable)
	unlinked := core.NewWebhook(app)
	unlinked.SetName("unlinked")
	unlinked.SetURI("https://example.com/unlinked")
	unlinked.SetTopics([]string{"demo2.update"})
	if err := app.Save(unlinked); err != nil {
		t.Fatal(err)
	}

	notViewable := core.NewWebhook(app)
	notViewable.SetName("not viewable")
	notViewable.SetURI("https://example.com/not-viewable")
	notViewable.SetTopics([]string{"users.update"})
	if err := app.Save(notViewable); err != nil {
		t.Fatal(err)
	}

	for _, s := range []struct {
		id     string
		method string
		token  string
		status int
	}{
		{linked.Id, http.MethodGet, staffToken, 403},
		{linked.Id, http.MethodPost, staffToken, 403},
		{linked.Id, http.MethodGet, ownerToken, 200},
		{unlinked.Id, http.MethodGet, staffToken, 200},
		{notViewable.Id, http.MethodGet, staffToken, 403},
		{notViewable.Id, http.MethodPost, staffToken, 403},
		{notViewable.Id, http.MethodGet, ownerToken, 200},
	} {
		path := "/secret"
		if s.method == http.MethodPost {
			path = "/rotate-secret"
		}
		res, body := b.do(s.method, "/api/webhooks/subscriptions/"+s.id+path, "", map[string]string{"Authorization": s.token})
		b.expectStatus(res, body, s.status)
	}
}
