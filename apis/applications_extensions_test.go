package apis_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
)

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

const extLaunchTokenType = "urn:pocketbase:params:oauth:token-type:launch_token"

// extInstall imports and installs a custom application with the extensions:
//   - "home" (navigation)
//   - "demo2-act" (record action of demo2)
//   - "demo1-act" (record action of demo1)
func extInstall(t testing.TB, app core.App, handle string, grant core.Permissions) *core.ApplicationInstallResult {
	t.Helper()

	// the launch endpoints require the request origin (of the test requests) to be the issuer origin
	app.Settings().Meta.AppURL = "http://example.com"

	raw := `{
		"handle": "` + handle + `",
		"name": "Ext ` + handle + `",
		"version": "1.0.0",
		"application_url": "https://ext.example.com",
		"extensions": [
			{"type": "dashboard.navigation", "handle": "home", "label": "Ext home", "path": "/pb/home"},
			{"type": "dashboard.record_action", "handle": "demo2-act", "label": "Inspect demo2", "path": "/pb/demo2", "collection": "demo2"},
			{"type": "dashboard.record_action", "handle": "demo1-act", "label": "Inspect demo1", "path": "/pb/demo1", "collection": "demo1"}
		]
	}`

	manifest, err := core.ParseApplicationManifest([]byte(raw), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, grant, "")
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// extStaffSession creates a dashboard (pb_dashboard client) session of the staff member with the provided email
// and returns the session and its access token.
func extStaffSession(t testing.TB, app core.App, email string) (*core.AuthSession, string) {
	t.Helper()

	staff, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, email)
	if err != nil {
		t.Fatal(err)
	}

	session, err := tests.CreateAuthSession(app, staff)
	if err != nil {
		t.Fatal(err)
	}

	token, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	return session, token
}

// extCreateStaff creates a staff member with a role with the provided permissions.
func extCreateStaff(t testing.TB, app core.App, email string, permissions core.Permissions) {
	t.Helper()

	role, err := tests.CreateRole(app, "role "+email, permissions)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tests.CreateStaff(app, email, role.Id); err != nil {
		t.Fatal(err)
	}
}

// extLaunch calls the launch endpoint and returns the status and the decoded response.
func extLaunch(t testing.TB, app core.App, token string, installationId string, extension string, recordId string) (int, map[string]any) {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"extension": extension, "recordId": recordId})

	status, raw := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installationId+"/launch", token, string(body))

	data := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &data)

	return status, data
}

// extMustLaunch returns a launch token of the provided extension (expects 200).
func extMustLaunch(t testing.TB, app core.App, token string, installationId string, extension string, recordId string) string {
	t.Helper()

	status, data := extLaunch(t, app, token, installationId, extension, recordId)
	if status != 200 {
		t.Fatalf("Expected launch 200, got %d %v", status, data)
	}

	launchToken, _ := data["launchToken"].(string)
	if launchToken == "" {
		t.Fatalf("Missing launchToken in %v", data)
	}

	return launchToken
}

// extExchange exchanges the provided launch token with the managed client credentials.
func extExchange(t testing.TB, app core.App, installed *core.ApplicationInstallResult, launchToken string, extra url.Values) (int, map[string]any) {
	t.Helper()

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {launchToken},
		"subject_token_type": {extLaunchTokenType},
	}
	for k, v := range extra {
		form[k] = v
	}

	return appTokenRequest(t, app, appTokenURL, form, map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
}

// extOnlineToken launches the "home" extension as the provided staff member and exchanges the launch token.
func extOnlineToken(t testing.TB, app core.App, installed *core.ApplicationInstallResult, email string) (string, *core.AuthSession) {
	t.Helper()

	session, staffToken := extStaffSession(t, app, email)

	launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

	status, data := extExchange(t, app, installed, launchToken, nil)
	if status != 200 {
		t.Fatalf("Expected the exchange 200, got %d %v", status, data)
	}

	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("Missing access_token in %v", data)
	}

	return token, session
}

func extEndRootSession(t testing.TB, app core.App, session *core.AuthSession) {
	t.Helper()

	root, err := app.FindAuthSessionById(session.Parent())
	if err != nil {
		t.Fatal(err)
	}

	if err := root.End(); err != nil {
		t.Fatal(err)
	}

	if err := app.Save(root); err != nil {
		t.Fatal(err)
	}
}

// -------------------------------------------------------------------
// Launch endpoint and extensions list
// -------------------------------------------------------------------

func TestApplicationExtensionsLaunch(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")

	// demo2 all + demo1 list only (no view => the demo1 record action is never available)
	installed := extInstall(t, app, "ext-app", core.Permissions{
		Collections: map[string][]string{
			demo1.Id: {core.PermissionActionList},
			demo2.Id: core.PermissionCollectionActions,
		},
	})

	extCreateStaff(t, app, "extstaff@example.com", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}, demo1.Id: core.PermissionCollectionActions},
		System:      map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead},
	})
	extCreateStaff(t, app, "appsonly@example.com", core.Permissions{
		System: map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead},
	})
	extCreateStaff(t, app, "noapps@example.com", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	})

	ownerSession, ownerToken := extStaffSession(t, app, "test@example.com")
	_, staffToken := extStaffSession(t, app, "extstaff@example.com")
	_, appsOnlyToken := extStaffSession(t, app, "appsonly@example.com")
	_, noAppsToken := extStaffSession(t, app, "noapps@example.com")

	demo2Record, err := app.FindFirstRecordByFilter("demo2", "id != ''")
	if err != nil {
		t.Fatal(err)
	}
	demo1Record, err := app.FindFirstRecordByFilter("demo1", "id != ''")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("navigation launch", func(t *testing.T) {
		status, data := extLaunch(t, app, ownerToken, installed.Installation.Id, "home", "")
		if status != 200 || data["url"] != "https://ext.example.com/pb/home" {
			t.Fatalf("Expected the extension url, got %d %v", status, data)
		}

		claims, err := core.ParseApplicationLaunchToken(app, data["launchToken"].(string))
		if err != nil {
			t.Fatal(err)
		}

		if claims.ClientId != installed.Client.ClientId() ||
			claims.StaffId != ownerSession.RecordRef() ||
			claims.StaffSessionId != ownerSession.Id ||
			claims.InstallationId != installed.Installation.Id ||
			claims.Extension != "home" ||
			claims.Record != nil {
			t.Fatalf("Unexpected launch claims %+v", claims)
		}
	})

	t.Run("record action launch", func(t *testing.T) {
		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "demo2-act", demo2Record.Id)

		claims, err := core.ParseApplicationLaunchToken(app, launchToken)
		if err != nil {
			t.Fatal(err)
		}

		if claims.Record == nil || claims.Record.Collection != "demo2" || claims.Record.Id != demo2Record.Id || claims.Extension != "demo2-act" {
			t.Fatalf("Unexpected record action claims %+v", claims)
		}
	})

	t.Run("denied launches", func(t *testing.T) {
		scenarios := []struct {
			name      string
			token     string
			extension string
			recordId  string
			status    int
		}{
			{"guest", "", "home", "", 401},
			{"no applications read", noAppsToken, "home", "", 403},
			{"the grant doesn't cover the collection view (Owner)", ownerToken, "demo1-act", demo1Record.Id, 403},
			{"the staff can't view the collection", appsOnlyToken, "demo2-act", demo2Record.Id, 403},
			{"missing record", ownerToken, "demo2-act", "missing", 404},
			{"record of another collection", ownerToken, "demo2-act", demo1Record.Id, 404},
			{"record action without record", ownerToken, "demo2-act", "", 400},
			{"navigation with record", ownerToken, "home", demo2Record.Id, 400},
			{"unknown extension", ownerToken, "missing", "", 404},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				status, data := extLaunch(t, app, s.token, installed.Installation.Id, s.extension, s.recordId)
				if status != s.status {
					t.Fatalf("Expected %d, got %d %v", s.status, status, data)
				}
			})
		}
	})

	t.Run("non-dashboard tokens", func(t *testing.T) {
		// the application installation offline token
		appToken := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")
		if status, data := extLaunch(t, app, appToken, installed.Installation.Id, "home", ""); status != 403 {
			t.Fatalf("Expected the application token to be rejected, got %d %v", status, data)
		}

		// an online token
		onlineToken, _ := extOnlineToken(t, app, installed, "test@example.com")
		if status, data := extLaunch(t, app, onlineToken, installed.Installation.Id, "home", ""); status != 403 {
			t.Fatalf("Expected the online token to be rejected, got %d %v", status, data)
		}

		// another first-party client of the _superusers issuer (not the dashboard)
		superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
		tool := core.NewOAuth2Client(app)
		tool.SetName("Staff tool")
		tool.SetClientId("staff_tool")
		tool.SetType(core.OAuth2ClientTypePublic)
		tool.SetFirstParty(true)
		tool.SetCollectionRef(superusers.Id)
		tool.SetRedirectURIs([]string{"https://tool.example.com/callback"})
		if err := app.Save(tool); err != nil {
			t.Fatal(err)
		}
		owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
		toolSession, err := app.CreateAuthSession(owner, tool, core.AuthSessionOptions{Parent: ownerSession.Parent()})
		if err != nil {
			t.Fatal(err)
		}
		toolToken, err := toolSession.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}
		if status, data := extLaunch(t, app, toolToken, installed.Installation.Id, "home", ""); status != 403 {
			t.Fatalf("Expected the non-dashboard first-party token to be rejected, got %d %v", status, data)
		}
	})

	t.Run("extensions list", func(t *testing.T) {
		list := func(token string) (int, []string) {
			status, raw := appApi(t, app, http.MethodGet, "/api/applications/extensions", token, "")
			items := []map[string]any{}
			_ = json.Unmarshal([]byte(raw), &items)
			handles := []string{}
			for _, item := range items {
				handles = append(handles, item["handle"].(string))
				if item["installationId"] != installed.Installation.Id || item["applicationName"] != "Ext ext-app" {
					t.Fatalf("Unexpected extension item %v", item)
				}
			}
			return status, handles
		}

		scenarios := []struct {
			name    string
			token   string
			status  int
			handles []string
		}{
			{"Owner (grant doesn't cover demo1 view)", ownerToken, 200, []string{"home", "demo2-act"}},
			{"staff with demo2 view", staffToken, 200, []string{"home", "demo2-act"}},
			{"staff without demo2 view", appsOnlyToken, 200, []string{"home"}},
			{"staff without applications read", noAppsToken, 403, []string{}},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				status, handles := list(s.token)
				if status != s.status || !slices.Equal(handles, s.handles) {
					t.Fatalf("Expected %d %v, got %d %v", s.status, s.handles, status, handles)
				}
			})
		}
	})

	t.Run("inactive installation", func(t *testing.T) {
		if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'pending' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'active' WHERE id = {:id}").
				Bind(map[string]any{"id": installed.Installation.Id}).Execute()
		}()

		if status, data := extLaunch(t, app, ownerToken, installed.Installation.Id, "home", ""); status != 403 {
			t.Fatalf("Expected the pending installation launch to be rejected, got %d %v", status, data)
		}

		status, raw := appApi(t, app, http.MethodGet, "/api/applications/extensions", ownerToken, "")
		if status != 200 || raw != "[]" {
			t.Fatalf("Expected no extensions of the pending installation, got %d %s", status, raw)
		}
	})
}

// -------------------------------------------------------------------
// Token exchange (launch token => online token)
// -------------------------------------------------------------------

func TestApplicationExtensionsTokenExchange(t *testing.T) {
	t.Parallel()

	newApp := func(t testing.TB) (*tests.TestApp, *core.ApplicationInstallResult) {
		app, err := tests.NewTestApp()
		if err != nil {
			t.Fatal(err)
		}

		demo2, _ := app.FindCollectionByNameOrId("demo2")

		installed := extInstall(t, app, "ext-app", core.Permissions{
			Collections: map[string][]string{demo2.Id: {"list", "view"}},
			System:      map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead},
		})

		return app, installed
	}

	t.Run("good exchange", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		events := 0
		app.OnOAuth2TokenRequest().BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
			events++
			return e.Next()
		})

		session, staffToken := extStaffSession(t, app, "test@example.com")
		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

		status, data := extExchange(t, app, installed, launchToken, nil)
		if status != 200 {
			t.Fatalf("Expected 200, got %d %v", status, data)
		}

		superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)

		user, _ := data["associated_user"].(map[string]any)
		roles, _ := user["roles"].([]any)
		if data["token_type"] != "Bearer" ||
			data["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" ||
			data["scope"] != "read_demo2 system:read_logs" ||
			data["refresh_token"] != nil ||
			data["id_token"] != nil ||
			data["expires_in"] != float64(superusers.AuthToken.Duration) ||
			user["id"] != session.RecordRef() ||
			user["email"] != nil ||
			len(roles) != 1 || roles[0] != core.RoleNameOwner {
			t.Fatalf("Unexpected online token response %v", data)
		}

		if events != 1 {
			t.Fatalf("Expected 1 OnOAuth2TokenRequest event, got %d", events)
		}

		claims := decodeTestJWT(t, data["access_token"].(string))
		if claims["id"] != session.RecordRef() || claims["cid"] != installed.Client.ClientId() || claims["act"] != nil {
			t.Fatalf("Unexpected online token claims %v", claims)
		}

		online, err := app.FindAuthSessionById(claims["sid"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if !online.IsLaunch() || online.Parent() != session.Parent() || online.LaunchJti() == "" || online.HasRefreshToken() ||
			online.Client() != installed.Client.Id || online.ExpiresAt().Time().After(time.Now().Add(superusers.AuthToken.DurationTime()+time.Second)) {
			t.Fatalf("Unexpected online session %v", online.PublicExport())
		}

		// replay
		status, data = extExchange(t, app, installed, launchToken, nil)
		if status != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected the replayed launch token to be rejected, got %d %v", status, data)
		}

		// narrowed scope
		launchToken = extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		status, data = extExchange(t, app, installed, launchToken, url.Values{"scope": {"read_demo2"}})
		if status != 200 || data["scope"] != "read_demo2" {
			t.Fatalf("Expected the narrowed scope, got %d %v", status, data)
		}

		// scope beyond staff ∩ grant
		launchToken = extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		status, data = extExchange(t, app, installed, launchToken, url.Values{"scope": {"write_demo2"}})
		if status != 400 || data["error"] != "invalid_scope" {
			t.Fatalf("Expected invalid_scope, got %d %v", status, data)
		}
	})

	t.Run("rejected exchanges", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		other := extInstall(t, app, "ext-other", core.Permissions{})

		_, staffToken := extStaffSession(t, app, "test@example.com")

		installations, _ := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
		signingKey, _ := installations.OAuth2Server.ActiveSigningKey()
		signer, err := signingKey.Signer()
		if err != nil {
			t.Fatal(err)
		}

		ownerSession, _ := extStaffSession(t, app, "test@example.com")
		expired, err := security.NewSignedJWTWithType(jwt.MapClaims{
			"iss":             core.OAuth2Issuer(app, installations),
			"aud":             installed.Client.ClientId(),
			"sub":             ownerSession.RecordRef(),
			"sid":             ownerSession.Id,
			"installation_id": installed.Installation.Id,
			"extension":       "home",
			"iat":             time.Now().Add(-2 * time.Minute).Unix(),
			"jti":             "expired_jti",
		}, signer, -time.Minute, core.ApplicationLaunchTokenType)
		if err != nil {
			t.Fatal(err)
		}

		scenarios := []struct {
			name     string
			client   *core.ApplicationInstallResult
			form     url.Values
			rawURL   string
			headers  func(installed *core.ApplicationInstallResult) map[string]string
			status   int
			expected string
		}{
			{
				name:     "expired",
				form:     url.Values{"subject_token": {expired}},
				status:   400,
				expected: "invalid_grant",
			},
			{
				name:     "wrong aud (other application client)",
				client:   other,
				status:   400,
				expected: "invalid_grant",
			},
			{
				name:     "wrong subject_token_type (impersonation)",
				form:     url.Values{"subject_token_type": {"urn:pocketbase:params:oauth:token-type:record_id"}},
				status:   400,
				expected: "unauthorized_client",
			},
			{
				name:     "unknown subject_token_type",
				form:     url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}},
				status:   400,
				expected: "invalid_request",
			},
			{
				name:     "with actor_token",
				form:     url.Values{"actor_token": {staffToken}, "actor_token_type": {"urn:ietf:params:oauth:token-type:access_token"}},
				status:   400,
				expected: "invalid_request",
			},
			{
				name:     "the staff dashboard token as subject",
				form:     url.Values{"subject_token": {staffToken}},
				status:   400,
				expected: "invalid_grant",
			},
			{
				name:   "query credentials",
				rawURL: appTokenURL + "?client_id=" + installed.Client.ClientId() + "&client_secret=" + installed.ClientSecret,
				headers: func(installed *core.ApplicationInstallResult) map[string]string {
					return nil
				},
				status:   401,
				expected: "invalid_client",
			},
			{
				name: "the dashboard client",
				headers: func(installed *core.ApplicationInstallResult) map[string]string {
					return map[string]string{}
				},
				form:     url.Values{"client_id": {core.OAuth2DashboardClientId}},
				status:   400,
				expected: "unauthorized_client",
			},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

				client := installed
				if s.client != nil {
					client = s.client
				}

				form := url.Values{
					"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"subject_token":      {launchToken},
					"subject_token_type": {extLaunchTokenType},
				}
				for k, v := range s.form {
					form[k] = v
				}

				headers := map[string]string{"Authorization": basicAuth(client.Client.ClientId(), client.ClientSecret)}
				if s.headers != nil {
					headers = s.headers(client)
				}

				rawURL := appTokenURL
				if s.rawURL != "" {
					rawURL = s.rawURL
				}

				status, data := appTokenRequest(t, app, rawURL, form, headers)
				if status != s.status || data["error"] != s.expected {
					t.Fatalf("Expected %d %s, got %d %v", s.status, s.expected, status, data)
				}
			})
		}

		// the launch tokens are exchangeable only at the installations issuer
		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		status, data := appTokenRequest(t, app, "/oauth2/"+core.CollectionNameSuperusers+"/token", url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {launchToken},
			"subject_token_type": {extLaunchTokenType},
			"client_id":          {core.OAuth2DashboardClientId},
		}, nil)
		if status != 400 || data["error"] != "unauthorized_client" {
			t.Fatalf("Expected the dashboard client launch exchange to be rejected, got %d %v", status, data)
		}

		// no online session was created by the rejected exchanges
		total, err := app.CountRecords(core.CollectionNameAuthSessions, nil)
		if err != nil {
			t.Fatal(err)
		}
		launches, err := app.FindAllRecords(core.CollectionNameAuthSessions)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range launches {
			if r.GetString("launchJti") != "" {
				t.Fatalf("Expected no online sessions (total %d), got %v", total, r.PublicExport())
			}
		}
	})

	t.Run("staff logged out before the exchange", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		session, staffToken := extStaffSession(t, app, "test@example.com")
		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

		extEndRootSession(t, app, session)

		status, data := extExchange(t, app, installed, launchToken, nil)
		if status != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant, got %d %v", status, data)
		}
	})

	t.Run("dashboard session ended before the exchange", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		session, staffToken := extStaffSession(t, app, "test@example.com")
		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

		if err := session.End(); err != nil {
			t.Fatal(err)
		}
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		status, data := extExchange(t, app, installed, launchToken, nil)
		if status != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant, got %d %v", status, data)
		}
	})

	t.Run("secret rotation and uninstall end the online sessions", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		token, _ := extOnlineToken(t, app, installed, "test@example.com")
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", token, ""); status != 200 {
			t.Fatalf("Expected 200 before the rotation, got %d %s", status, body)
		}

		installation, err := app.FindApplicationInstallationById(installed.Installation.Id)
		if err != nil {
			t.Fatal(err)
		}
		client, secret, err := app.RotateApplicationInstallationSecret(installation)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the online token to be rejected after the secret rotation, got %d %s", status, body)
		}

		rotated := &core.ApplicationInstallResult{Installation: installation, Client: client, ClientSecret: secret}
		token, _ = extOnlineToken(t, app, rotated, "test@example.com")
		if err := app.Delete(installation); err != nil {
			t.Fatal(err)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the online token to be rejected after the uninstall, got %d %s", status, body)
		}
	})

	t.Run("installation uninstalled or pending before the exchange", func(t *testing.T) {
		app, installed := newApp(t)
		defer app.Cleanup()

		_, staffToken := extStaffSession(t, app, "test@example.com")

		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'pending' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		status, data := extExchange(t, app, installed, launchToken, nil)
		if status != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected the pending installation exchange to be rejected, got %d %v", status, data)
		}
		if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'active' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
			t.Fatal(err)
		}

		launchToken = extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		if err := app.Delete(installed.Installation); err != nil {
			t.Fatal(err)
		}
		status, data = extExchange(t, app, installed, launchToken, nil)
		if status != 401 || data["error"] != "invalid_client" {
			t.Fatalf("Expected the uninstalled client to be rejected, got %d %v", status, data)
		}
	})
}

// -------------------------------------------------------------------
// Online tokens (staff ∩ grant)
// -------------------------------------------------------------------

func TestApplicationExtensionsOnlineTokenAuthorize(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")

	// narrow grant: demo2 list/view only
	narrow := extInstall(t, app, "ext-narrow", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	})

	// broad grant: demo1 + demo2 all, logs, settings and collections read, webhooks write
	broad := extInstall(t, app, "ext-broad", core.Permissions{
		Collections: map[string][]string{
			demo1.Id: core.PermissionCollectionActions,
			demo2.Id: core.PermissionCollectionActions,
		},
		System: map[string]string{
			core.PermissionResourceLogs:        core.PermissionLevelRead,
			core.PermissionResourceSettings:    core.PermissionLevelRead,
			core.PermissionResourceCollections: core.PermissionLevelRead,
			core.PermissionResourceWebhooks:    core.PermissionLevelWrite,
		},
	})

	// limited staff: demo2 list/view, logs read, webhooks write, applications read
	extCreateStaff(t, app, "limited@example.com", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System: map[string]string{
			core.PermissionResourceLogs:         core.PermissionLevelRead,
			core.PermissionResourceWebhooks:     core.PermissionLevelWrite,
			core.PermissionResourceApplications: core.PermissionLevelRead,
		},
	})

	ownerNarrow, _ := extOnlineToken(t, app, narrow, "test@example.com")
	ownerBroad, _ := extOnlineToken(t, app, broad, "test@example.com")
	limitedBroad, limitedSession := extOnlineToken(t, app, broad, "limited@example.com")

	demo2Record, _ := app.FindFirstRecordByFilter("demo2", "id != ''")

	webhookBody := `{"name":"x","uri":"https://hooks.example.com/x","topics":["demo2.create"]}`

	scenarios := []struct {
		name   string
		token  string
		method string
		url    string
		body   string
		status int
	}{
		// Owner staff ∩ narrow grant != Owner
		{"Owner ∩ narrow: demo2 list", ownerNarrow, http.MethodGet, "/api/collections/demo2/records", "", 200},
		{"Owner ∩ narrow: demo2 view", ownerNarrow, http.MethodGet, "/api/collections/demo2/records/" + demo2Record.Id, "", 200},
		{"Owner ∩ narrow: demo2 create", ownerNarrow, http.MethodPost, "/api/collections/demo2/records", `{}`, 403},
		{"Owner ∩ narrow: demo1 list", ownerNarrow, http.MethodGet, "/api/collections/demo1/records", "", 403},
		{"Owner ∩ narrow: settings", ownerNarrow, http.MethodGet, "/api/settings", "", 403},
		{"Owner ∩ narrow: logs", ownerNarrow, http.MethodGet, "/api/logs", "", 403},
		{"Owner ∩ narrow: roles", ownerNarrow, http.MethodGet, "/api/roles", "", 403},
		{"Owner ∩ narrow: applications", ownerNarrow, http.MethodGet, "/api/applications", "", 403},
		{"Owner ∩ narrow: superusers", ownerNarrow, http.MethodGet, "/api/collections/_superusers/records", "", 403},
		{"Owner ∩ narrow: sql", ownerNarrow, http.MethodPost, "/api/sql", `{"query":"select 1"}`, 403},
		{"Owner ∩ narrow: file token", ownerNarrow, http.MethodPost, "/api/files/token", "", 403},

		// Owner staff ∩ broad grant = grant (webhooks at most read)
		{"Owner ∩ broad: demo1 create", ownerBroad, http.MethodPost, "/api/collections/demo1/records", `{"text":"x"}`, 200},
		{"Owner ∩ broad: settings", ownerBroad, http.MethodGet, "/api/settings", "", 200},
		{"Owner ∩ broad: logs", ownerBroad, http.MethodGet, "/api/logs", "", 200},
		{"Owner ∩ broad: superusers", ownerBroad, http.MethodGet, "/api/collections/_superusers/records", "", 403},
		{"Owner ∩ broad: webhook topics", ownerBroad, http.MethodGet, "/api/webhooks/topics", "", 200},
		{"Owner ∩ broad: webhooks list", ownerBroad, http.MethodGet, "/api/collections/_webhooks/records", "", 200},
		{"Owner ∩ broad: webhooks create", ownerBroad, http.MethodPost, "/api/collections/_webhooks/records", webhookBody, 403},
		{"Owner ∩ broad: settings write", ownerBroad, http.MethodPatch, "/api/settings", `{}`, 403},

		// limited staff ∩ broad grant != grant
		{"limited ∩ broad: demo2 list", limitedBroad, http.MethodGet, "/api/collections/demo2/records", "", 200},
		{"limited ∩ broad: demo2 create", limitedBroad, http.MethodPost, "/api/collections/demo2/records", `{}`, 403},
		{"limited ∩ broad: demo1 list", limitedBroad, http.MethodGet, "/api/collections/demo1/records", "", 403},
		{"limited ∩ broad: logs", limitedBroad, http.MethodGet, "/api/logs", "", 200},
		{"limited ∩ broad: settings", limitedBroad, http.MethodGet, "/api/settings", "", 403},
		{"limited ∩ broad: webhooks create", limitedBroad, http.MethodPost, "/api/collections/_webhooks/records", webhookBody, 403},
		{"limited ∩ broad: applications", limitedBroad, http.MethodGet, "/api/applications", "", 403},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			status, body := appApi(t, app, s.method, s.url, s.token, s.body)
			if status != s.status {
				t.Fatalf("Expected %d, got %d %s", s.status, status, body)
			}
		})
	}

	t.Run("permissions/me", func(t *testing.T) {
		status, raw := appApi(t, app, http.MethodGet, "/api/permissions/me", ownerNarrow, "")
		if status != 200 {
			t.Fatalf("Expected 200, got %d %s", status, raw)
		}

		data := map[string]any{}
		_ = json.Unmarshal([]byte(raw), &data)

		onBehalfOf, _ := data["onBehalfOf"].(map[string]any)
		application, _ := data["application"].(map[string]any)
		permissions, _ := data["permissions"].(map[string]any)
		collections, _ := permissions["collections"].(map[string]any)
		system, _ := permissions["system"].(map[string]any)
		if data["kind"] != core.ActorKindStaff ||
			data["owner"] != false ||
			onBehalfOf["kind"] != core.ActorKindApplication ||
			onBehalfOf["installationId"] != narrow.Installation.Id ||
			application["handle"] != "ext-narrow" ||
			application["clientId"] != narrow.Client.ClientId() ||
			len(collections) != 1 || collections[demo2.Id] == nil ||
			len(system) != 0 {
			t.Fatalf("Unexpected online permissions %s", raw)
		}

		// limited staff ∩ broad grant
		status, raw = appApi(t, app, http.MethodGet, "/api/permissions/me", limitedBroad, "")
		data = map[string]any{}
		_ = json.Unmarshal([]byte(raw), &data)
		permissions, _ = data["permissions"].(map[string]any)
		system, _ = permissions["system"].(map[string]any)
		if status != 200 || system[core.PermissionResourceLogs] != "read" || system[core.PermissionResourceWebhooks] != "read" ||
			system[core.PermissionResourceApplications] != nil || system[core.PermissionResourceSettings] != nil {
			t.Fatalf("Unexpected limited online permissions %d %s", status, raw)
		}
	})

	t.Run("grant narrowing applies live", func(t *testing.T) {
		token, _ := extOnlineToken(t, app, narrow, "test@example.com")

		installation, err := app.FindApplicationInstallationById(narrow.Installation.Id)
		if err != nil {
			t.Fatal(err)
		}
		installation.SetPermissions(core.Permissions{Collections: map[string][]string{demo2.Id: {"view"}}})
		if err := app.Save(installation); err != nil {
			t.Fatal(err)
		}

		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", token, ""); status != 403 {
			t.Fatalf("Expected the narrowed grant to deny the list, got %d %s", status, body)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records/"+demo2Record.Id, token, ""); status != 200 {
			t.Fatalf("Expected the view to be still allowed, got %d %s", status, body)
		}
	})

	t.Run("staff logout ends the online session", func(t *testing.T) {
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", limitedBroad, ""); status != 200 {
			t.Fatalf("Expected 200 before the logout, got %d %s", status, body)
		}

		extEndRootSession(t, app, limitedSession)

		if status, body := appApi(t, app, http.MethodGet, "/api/permissions/me", limitedBroad, ""); status != 401 {
			t.Fatalf("Expected the online token to be rejected after the staff logout, got %d %s", status, body)
		}
	})
}

// -------------------------------------------------------------------
// The launch token is never an auth token
// -------------------------------------------------------------------

func TestApplicationLaunchTokenNeverAuth(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installed := extInstall(t, app, "ext-app", core.Permissions{
		Collections: map[string][]string{demo2.Id: core.PermissionCollectionActions},
	})

	_, staffToken := extStaffSession(t, app, "test@example.com")
	launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")

	for _, auth := range []string{launchToken, "Bearer " + launchToken} {
		// records API (deny by default: neither an API key nor a valid access token)
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", auth, ""); status != 401 {
			t.Fatalf("Expected the records API to reject the launch token, got %d %s", status, body)
		}

		// permissions/me
		if status, body := appApi(t, app, http.MethodGet, "/api/permissions/me", auth, ""); status != 401 {
			t.Fatalf("Expected permissions/me to reject the launch token, got %d %s", status, body)
		}

		// file token
		if status, body := appApi(t, app, http.MethodPost, "/api/files/token", auth, ""); status != 401 {
			t.Fatalf("Expected the file token endpoint to reject the launch token, got %d %s", status, body)
		}

		// launch endpoint itself
		if status, body := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installed.Installation.Id+"/launch", auth, `{"extension":"home"}`); status != 401 {
			t.Fatalf("Expected the launch endpoint to reject the launch token, got %d %s", status, body)
		}

		// userinfo (of every issuer)
		for _, issuer := range []string{core.CollectionNameSuperusers, "users"} {
			res := oauth2Mux(t, app).do(http.MethodGet, "/oauth2/"+issuer+"/userinfo", nil, map[string]string{"Authorization": auth})
			res.Body.Close()
			if res.StatusCode != 401 {
				t.Fatalf("[%s] Expected userinfo to reject the launch token, got %d", issuer, res.StatusCode)
			}
		}
	}

	// realtime subscription
	client := subscriptions.NewDefaultClient()
	app.SubscriptionsBroker().Register(client)
	status, body := appApi(t, app, http.MethodPost, "/api/realtime", launchToken, `{"clientId":"`+client.Id()+`","subscriptions":["demo2"]}`)
	if status != 401 || client.Get(apis.RealtimeClientAuthKey) != nil {
		t.Fatalf("Expected the realtime subscription to reject the launch token, got %d %s", status, body)
	}

	// introspection by the token audience (the managed client)
	status, data := appTokenRequest(t, app, "/oauth2/"+core.CollectionNameApplicationInstallations+"/introspect", url.Values{"token": {launchToken}},
		map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
	if status != 200 || data["active"] != false {
		t.Fatalf("Expected the launch token introspection to be inactive, got %d %v", status, data)
	}

	// impersonation actor token
	status, data = appTokenRequest(t, app, "/oauth2/users/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {core.OAuth2DashboardClientId},
		"subject_token":      {"4q1xlclmfloku33"},
		"subject_token_type": {"urn:pocketbase:params:oauth:token-type:record_id"},
		"actor_token":        {launchToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
	}, nil)
	if status != 400 || data["error"] != "invalid_grant" {
		t.Fatalf("Expected the launch token to be rejected as impersonation actor token, got %d %v", status, data)
	}

	// still exchangeable (it wasn't consumed by the rejected attempts)
	if status, data := extExchange(t, app, installed, launchToken, nil); status != 200 {
		t.Fatalf("Expected the launch token to be still exchangeable, got %d %v", status, data)
	}

}

// -------------------------------------------------------------------
// Staff identity semantics (IsStaff, SuperuserIPs, introspection)
// -------------------------------------------------------------------

func TestApplicationExtensionsStaffSemantics(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installed := extInstall(t, app, "ext-app", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	})
	other := extInstall(t, app, "ext-other", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	})

	ownerSession, ownerToken := extStaffSession(t, app, "test@example.com")
	onlineToken, _ := extOnlineToken(t, app, installed, "test@example.com")
	appOfflineToken := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

	// a (normally not allowed) third-party client of the _superusers issuer
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	thirdParty := core.NewOAuth2Client(app)
	thirdParty.SetName("Staff third-party")
	thirdParty.SetClientId("staff_3p")
	thirdParty.SetType(core.OAuth2ClientTypePublic)
	thirdParty.SetCollectionRef(superusers.Id)
	thirdParty.SetRedirectURIs([]string{"https://3p.example.com/callback"})
	if err := app.SaveNoValidate(thirdParty); err != nil {
		t.Fatal(err)
	}
	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	thirdPartySession, err := app.CreateAuthSession(owner, thirdParty, core.AuthSessionOptions{Parent: ownerSession.Parent()})
	if err != nil {
		t.Fatal(err)
	}
	thirdPartyToken, err := thirdPartySession.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("health details only for the staff acting directly", func(t *testing.T) {
		scenarios := []struct {
			name    string
			token   string
			details bool
		}{
			{"dashboard token", ownerToken, true},
			{"online token", onlineToken, false},
			{"third-party staff token", thirdPartyToken, false},
			{"application token", appOfflineToken, false},
			{"guest", "", false},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				status, body := appApi(t, app, http.MethodGet, "/api/health", s.token, "")
				if status != 200 || strings.Contains(body, "realIP") != s.details || strings.Contains(body, "canBackup") != s.details {
					t.Fatalf("Expected details %v, got %d %s", s.details, status, body)
				}
			})
		}
	})

	t.Run("collections list of an online token = staff ∩ grant", func(t *testing.T) {
		status, raw := appApi(t, app, http.MethodGet, "/api/collections?perPage=500", onlineToken, "")
		data := map[string]any{}
		_ = json.Unmarshal([]byte(raw), &data)
		items, _ := data["items"].([]any)
		names := []string{}
		for _, item := range items {
			names = append(names, item.(map[string]any)["name"].(string))
		}
		if status != 200 || !slices.Equal(names, []string{"demo2"}) {
			t.Fatalf("Expected only demo2, got %d %v", status, names)
		}

		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo1", onlineToken, ""); status != 403 && status != 404 {
			t.Fatalf("Expected demo1 to be denied, got %d %s", status, body)
		}

		// third-party staff tokens are not staff for the collections API
		if status, body := appApi(t, app, http.MethodGet, "/api/collections", thirdPartyToken, ""); status != 403 {
			t.Fatalf("Expected the third-party staff token to be denied, got %d %s", status, body)
		}
	})

	t.Run("introspection by the token client", func(t *testing.T) {
		introspect := func(client *core.ApplicationInstallResult, token string) map[string]any {
			status, data := appTokenRequest(t, app, "/oauth2/"+core.CollectionNameApplicationInstallations+"/introspect", url.Values{"token": {token}},
				map[string]string{"Authorization": basicAuth(client.Client.ClientId(), client.ClientSecret)})
			if status != 200 {
				t.Fatalf("Expected 200, got %d %v", status, data)
			}
			return data
		}

		claims := decodeTestJWT(t, onlineToken)

		data := introspect(installed, onlineToken)
		if data["active"] != true ||
			data["sub"] != owner.Id ||
			data["client_id"] != installed.Client.ClientId() ||
			data["scope"] != "read_demo2" ||
			data["sid"] != claims["sid"] ||
			data["exp"] != claims["exp"] {
			t.Fatalf("Unexpected online token introspection %v", data)
		}

		if data := introspect(other, onlineToken); data["active"] != false || len(data) != 1 {
			t.Fatalf("Expected another client introspection to be inactive, got %v", data)
		}

		// the token client could also revoke it
		token, _ := extOnlineToken(t, app, installed, "test@example.com")
		status, data := appTokenRequest(t, app, "/oauth2/"+core.CollectionNameApplicationInstallations+"/revoke", url.Values{"token": {token}},
			map[string]string{"Authorization": basicAuth(other.Client.ClientId(), other.ClientSecret)})
		if status != 200 {
			t.Fatalf("Expected 200, got %d %v", status, data)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", token, ""); status != 200 {
			t.Fatalf("Expected another client revocation to be ignored, got %d %s", status, body)
		}
		status, data = appTokenRequest(t, app, "/oauth2/"+core.CollectionNameApplicationInstallations+"/revoke", url.Values{"token": {token}},
			map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
		if status != 200 {
			t.Fatalf("Expected 200, got %d %v", status, data)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", token, ""); status != 401 {
			t.Fatalf("Expected the revoked online token to be rejected, got %d %s", status, body)
		}
	})

	t.Run("SuperuserIPs restrict every staff actor token", func(t *testing.T) {
		app.Settings().SuperuserIPs = []string{"1.2.3.4"}
		defer func() {
			app.Settings().SuperuserIPs = nil
		}()

		scenarios := []struct {
			name   string
			token  string
			status int
		}{
			{"dashboard token", ownerToken, 403},
			{"online token", onlineToken, 403},
			{"third-party staff token", thirdPartyToken, 403},
			{"application token (not a staff actor)", appOfflineToken, 200},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", s.token, "")
				if status != s.status {
					t.Fatalf("Expected %d, got %d %s", s.status, status, body)
				}
				if s.status == 403 && !strings.Contains(body, "including applications acting on behalf of a staff member") {
					t.Fatalf("Expected the explicit allowed IPs message, got %s", body)
				}
			})
		}

	})

	t.Run("applications list SuperuserIPs flag", func(t *testing.T) {
		_, raw := appApi(t, app, http.MethodGet, "/api/applications", ownerToken, "")
		if !strings.Contains(raw, `"superuserIPsRestricted":false`) {
			t.Fatalf("Expected the not restricted flag, got %s", raw)
		}

		app.Settings().SuperuserIPs = []string{"1.2.3.4", "192.0.2.1"}
		defer func() {
			app.Settings().SuperuserIPs = nil
		}()

		status, raw := appApi(t, app, http.MethodGet, "/api/applications", ownerToken, "")
		if status != 200 || !strings.Contains(raw, `"superuserIPsRestricted":true`) {
			t.Fatalf("Expected the restricted flag, got %d %s", status, raw)
		}
	})
}
