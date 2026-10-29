package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestPermissionsMe(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/permissions/me",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:   "Owner",
			Method: http.MethodGet,
			URL:    "/api/permissions/me",
			Headers: map[string]string{
				"Authorization": tests.AuthToken(core.CollectionNameSuperusers, "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"kind":"staff"`,
				`"owner":true`,
				`"registry":{`,
				`"resources":[{"name":"settings"`,
				`"actions":["list","view","create","update","delete"]`,
				`"_apiKeys":"oauth2_clients"`,
				`"_roles":"roles"`,
			},
		},
		{
			Name:   "customer",
			Method: http.MethodGet,
			URL:    "/api/permissions/me",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"kind":"customer"`,
				`"owner":false`,
				`"collections":[]`,
				`"registry":{`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestPermissionsMeRecord(t *testing.T) {
	t.Parallel()

	secretKeys := []string{"tokenKey", "password", "passwordConfirm"}

	me := func(t testing.TB, b *oauth2Browser, token string) map[string]any {
		t.Helper()

		res, body := b.do(http.MethodGet, "/api/permissions/me", "", map[string]string{"Authorization": token})
		b.expectStatus(res, body, http.StatusOK)

		for _, k := range secretKeys {
			if strings.Contains(body, `"`+k+`"`) {
				t.Fatalf("Unexpected secret field %q in %s", k, body)
			}
		}

		return parseJSONMap(t, body)
	}

	recordOf := func(data map[string]any) map[string]any {
		r, _ := data["record"].(map[string]any)
		return r
	}

	t.Run("limited staff without staff read", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		role, err := tests.CreateRole(app, "logs_reader", core.Permissions{System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead}})
		if err != nil {
			t.Fatal(err)
		}
		staff, err := tests.CreateStaff(app, "limited_staff@example.com", role.Id)
		if err != nil {
			t.Fatal(err)
		}
		token, err := tests.NewSessionAuthToken(app, staff)
		if err != nil {
			t.Fatal(err)
		}

		b := newOAuth2Browser(t, app)

		record := recordOf(me(t, b, token))
		if record == nil || record["id"] != staff.Id || record["email"] != staff.Email() || record["collectionName"] != core.CollectionNameSuperusers {
			t.Fatalf("Expected the own staff record, got %v", record)
		}

		// the regular record API is still denied
		res, body := b.do(http.MethodGet, "/api/collections/_superusers/records/"+staff.Id, "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected 403 for the _superusers record API, got %d %s", res.StatusCode, body)
		}
	})

	t.Run("Owner never gets the secret fields", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		owner := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		token, err := tests.NewSessionAuthToken(app, owner)
		if err != nil {
			t.Fatal(err)
		}

		record := recordOf(me(t, newOAuth2Browser(t, app), token))
		if record == nil || record["id"] != owner.Id || record["email"] != owner.Email() {
			t.Fatalf("Expected the own Owner record, got %v", record)
		}
	})

	t.Run("first-party customer", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		token, err := tests.NewSessionAuthToken(app, user)
		if err != nil {
			t.Fatal(err)
		}

		record := recordOf(me(t, newOAuth2Browser(t, app), token))
		if record == nil || record["id"] != user.Id || record["email"] != user.Email() {
			t.Fatalf("Expected the own customer record with email, got %v", record)
		}
	})

	t.Run("third-party scopes", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		client := oauth2FindClient(t, app, "3p")
		b := newOAuth2Browser(t, app)

		scenarios := []struct {
			scopes        []string
			expectRecord  bool
			expectedEmail bool
		}{
			{[]string{"openid"}, false, false},
			{[]string{"profile"}, false, false},
			{[]string{"posts:read"}, false, false},
			{[]string{"openid", "profile"}, true, false},
			{[]string{"email"}, true, true},
			{[]string{"openid", "email"}, true, true},
			{[]string{"openid", "profile", "email"}, true, true},
		}

		for _, s := range scenarios {
			token, _ := oauth2AccessToken(t, app, client, user, s.scopes)

			data := me(t, b, token)
			if data["thirdParty"] != true {
				t.Fatalf("%v: expected third-party actor", s.scopes)
			}

			record := recordOf(data)
			if (record != nil) != s.expectRecord {
				t.Fatalf("%v: expected record %v, got %v", s.scopes, s.expectRecord, record)
			}
			if record == nil {
				continue
			}

			if record["id"] != user.Id {
				t.Fatalf("%v: unexpected record %v", s.scopes, record)
			}

			_, hasEmail := record["email"]
			if hasEmail != s.expectedEmail || (hasEmail && record["email"] != user.Email()) {
				t.Fatalf("%v: expected email %v, got %v", s.scopes, s.expectedEmail, record["email"])
			}
		}
	})
}
