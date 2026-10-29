package core_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const testExtensionsManifestTOML = `
handle          = "ext-app"
name            = "Ext app"
version         = "1.0.0"
application_url = "https://ext.example.com/ignored/path"

[[extensions]]
type   = "dashboard.navigation"
handle = "home"
label  = "Ext home"
path   = "/pb/home?tab=1"

[[extensions]]
type       = "dashboard.record_action"
handle     = "inspect"
label      = "Inspect"
path       = "/pb/inspect"
collection = "demo2"
`

func TestApplicationManifestExtensions(t *testing.T) {
	t.Parallel()

	manifest, err := core.ParseApplicationManifest([]byte(testExtensionsManifestTOML), core.ApplicationManifestFormatTOML)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifest.Extensions) != 2 ||
		manifest.Extensions[0].Type != core.ApplicationExtensionTypeNavigation ||
		manifest.Extensions[1].Collection != "demo2" {
		t.Fatalf("Unexpected extensions %v", manifest.Extensions)
	}

	// stored in the normalized manifest (and parsed back)
	raw, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := core.ApplicationManifestFromJSON(raw)
	if err != nil || len(stored.Extensions) != 2 || stored.Extensions[1].Handle != "inspect" {
		t.Fatalf("Expected the extensions to be stored, got %s %v", raw, err)
	}

	ext, ok := manifest.FindExtension("home")
	if !ok {
		t.Fatal("Expected the home extension")
	}
	extURL, err := manifest.ExtensionURL(ext)
	if err != nil || extURL != "https://ext.example.com/pb/home?tab=1" {
		t.Fatalf("Expected the application_url origin + path, got %q %v", extURL, err)
	}

	if _, ok := manifest.FindExtension("missing"); ok {
		t.Fatal("Expected the missing extension to not be found")
	}

	// the canonical JSON of a manifest without extensions is unchanged
	plain, _ := core.ParseApplicationManifest([]byte(`{"handle":"ab","name":"a","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	plainRaw, _ := plain.JSON()
	if strings.Contains(string(plainRaw), "extensions") {
		t.Fatalf("Expected the extensions key to be omitted, got %s", plainRaw)
	}

	ext20 := make([]string, 21)
	for i := range ext20 {
		ext20[i] = `{"type":"dashboard.navigation","handle":"h` + strings.Repeat("x", i+1) + `","label":"x","path":"/x"}`
	}

	base := `"handle":"ab","name":"a","version":"1.0.0","application_url":"https://a.example.com"`

	scenarios := []struct {
		name       string
		raw        string
		expectKeys []string
	}{
		{
			"valid",
			`{` + base + `,"extensions":[{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/"},` +
				`{"type":"dashboard.record_action","handle":"act","label":"Act","path":"/a/b?c=d","collection":"posts"}]}`,
			nil,
		},
		{
			"unknown type (named key)",
			`{` + base + `,"extensions":[{"type":"dashboard.page","handle":"nav","label":"Nav","path":"/"}]}`,
			[]string{"extensions.0.type"},
		},
		{
			"unknown extension key",
			`{` + base + `,"extensions":[{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/","url":"https://x.com"}]}`,
			[]string{"extensions.0.url"},
		},
		{
			"not a list of tables",
			`{` + base + `,"extensions":{"type":"dashboard.navigation"}}`,
			[]string{"extensions"},
		},
		{
			"missing required",
			`{` + base + `,"extensions":[{"type":"dashboard.record_action"}]}`,
			[]string{"extensions.0.handle", "extensions.0.label", "extensions.0.path", "extensions.0.collection"},
		},
		{
			"duplicated handles",
			`{` + base + `,"extensions":[{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/"},{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/"}]}`,
			[]string{"extensions.1.handle"},
		},
		{
			"collection of a navigation extension",
			`{` + base + `,"extensions":[{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/","collection":"posts"}]}`,
			[]string{"extensions.0.collection"},
		},
		{
			"invalid record action collection",
			`{` + base + `,"extensions":[{"type":"dashboard.record_action","handle":"act","label":"Act","path":"/","collection":"po sts"}]}`,
			[]string{"extensions.0.collection"},
		},
		{
			"absolute, protocol relative and malformed paths",
			`{` + base + `,"extensions":[` +
				`{"type":"dashboard.navigation","handle":"p1","label":"x","path":"https://evil.example.com/x"},` +
				`{"type":"dashboard.navigation","handle":"p2","label":"x","path":"//evil.example.com/x"},` +
				`{"type":"dashboard.navigation","handle":"p3","label":"x","path":"x/y"},` +
				`{"type":"dashboard.navigation","handle":"p4","label":"x","path":"/\\evil.example.com"},` +
				`{"type":"dashboard.navigation","handle":"p5","label":"x","path":"/a b"},` +
				`{"type":"dashboard.navigation","handle":"p6","label":"x","path":"javascript:alert(1)"}]}`,
			[]string{"extensions.0.path", "extensions.1.path", "extensions.2.path", "extensions.3.path", "extensions.4.path", "extensions.5.path"},
		},
		{
			"extensions without application_url",
			`{"handle":"ab","name":"a","version":"1.0.0","extensions":[{"type":"dashboard.navigation","handle":"nav","label":"Nav","path":"/"}]}`,
			[]string{"extensions.0.path"},
		},
		{
			"too many extensions",
			`{` + base + `,"extensions":[` + strings.Join(ext20, ",") + `]}`,
			[]string{"extensions"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			_, err := core.ParseApplicationManifest([]byte(s.raw), core.ApplicationManifestFormatJSON)

			verrs, _ := err.(validation.Errors)
			if len(verrs) != len(s.expectKeys) {
				t.Fatalf("Expected error keys %v, got %v", s.expectKeys, err)
			}
			for _, k := range s.expectKeys {
				if verrs[k] == nil {
					t.Fatalf("Missing error key %q in %v", k, err)
				}
			}
		})
	}

	t.Run("the unknown type error names the key", func(t *testing.T) {
		_, err := core.ParseApplicationManifest([]byte(`{`+base+`,"extensions":[{"type":"x.y","handle":"nav","label":"Nav","path":"/"}]}`), core.ApplicationManifestFormatJSON)
		if err == nil || !strings.Contains(err.Error(), "extensions.0.type") {
			t.Fatalf("Expected the error to name the extensions.0.type key, got %v", err)
		}
	})
}

func TestPermissionsIntersect(t *testing.T) {
	t.Parallel()

	staff := core.Permissions{
		Collections: map[string][]string{"*": {"list", "view"}, "c1": {"create"}},
		System:      map[string]string{"logs": "write", "settings": "read", "webhooks": "write"},
	}
	grant := core.Permissions{
		Collections: map[string][]string{"*": {"list"}, "c1": {"view", "create", "delete"}, "c2": {"view", "update"}},
		System:      map[string]string{"logs": "read", "settings": "read", "crons": "write"},
	}

	result := staff.Intersect(grant)

	expectedCollections := map[string][]string{
		"*":  {"list"},
		"c1": {"create", "view"},
		"c2": {"view"},
	}
	if len(result.Collections) != len(expectedCollections) {
		t.Fatalf("Expected collections %v, got %v", expectedCollections, result.Collections)
	}
	for k, actions := range expectedCollections {
		got := slices.Clone(result.Collections[k])
		slices.Sort(got)
		want := slices.Clone(actions)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("[%s] Expected %v, got %v", k, want, got)
		}
	}

	expectedSystem := map[string]string{"logs": "read", "settings": "read"}
	if len(result.System) != len(expectedSystem) {
		t.Fatalf("Expected system %v, got %v", expectedSystem, result.System)
	}
	for k, v := range expectedSystem {
		if result.System[k] != v {
			t.Fatalf("[%s] Expected %q, got %q", k, v, result.System[k])
		}
	}

	// symmetric
	reversed := grant.Intersect(staff)
	if !reversed.Covers(result) || !result.Covers(reversed) {
		t.Fatalf("Expected a symmetric intersection, got %v vs %v", result, reversed)
	}
}

// installTestExtensionsApplication installs the testExtensionsManifestTOML application with the provided grant.
func installTestExtensionsApplication(t testing.TB, app core.App, grant core.Permissions) *core.ApplicationInstallResult {
	t.Helper()

	manifest, err := core.ParseApplicationManifest([]byte(testExtensionsManifestTOML), core.ApplicationManifestFormatTOML)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatTOML, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, grant, "")
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func TestApplicationLaunchToken(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	installed := installTestExtensionsApplication(t, app, core.Permissions{})

	claims := core.ApplicationLaunchClaims{
		ClientId:       installed.Client.ClientId(),
		StaffId:        "staff_id",
		StaffSessionId: "staff_session",
		InstallationId: installed.Installation.Id,
		Extension:      "inspect",
		Record:         &core.ApplicationLaunchRecord{Collection: "demo2", Id: "record_id"},
	}

	token, err := core.NewApplicationLaunchToken(app, claims)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("header and claims", func(t *testing.T) {
		rawHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(rawHeader), `"typ":"`+core.ApplicationLaunchTokenType+`"`) || !strings.Contains(string(rawHeader), `"kid":`) {
			t.Fatalf("Expected the typ and kid headers, got %s", rawHeader)
		}

		parsed, err := core.ParseApplicationLaunchToken(app, token)
		if err != nil {
			t.Fatal(err)
		}

		installations, _ := app.FindCachedCollectionByNameOrId(core.CollectionNameApplicationInstallations)
		if parsed.Issuer != core.OAuth2Issuer(app, installations) ||
			parsed.ClientId != claims.ClientId ||
			parsed.StaffId != "staff_id" ||
			parsed.StaffSessionId != "staff_session" ||
			parsed.InstallationId != installed.Installation.Id ||
			parsed.Extension != "inspect" ||
			parsed.Record == nil || parsed.Record.Collection != "demo2" || parsed.Record.Id != "record_id" ||
			parsed.Jti == "" ||
			parsed.ExpiresAt.Sub(time.Now()) > core.ApplicationLaunchTokenDuration+time.Second {
			t.Fatalf("Unexpected parsed claims %+v", parsed)
		}

		// never an auth token
		if _, err := app.FindAuthRecordByToken(token); err == nil {
			t.Fatal("Expected the launch token to never be accepted as a record token")
		}
	})

	t.Run("missing required claims", func(t *testing.T) {
		missing := claims
		missing.StaffSessionId = ""
		if _, err := core.NewApplicationLaunchToken(app, missing); err == nil {
			t.Fatal("Expected the missing sid to be rejected")
		}
	})

	t.Run("invalid tokens", func(t *testing.T) {
		installations, _ := app.FindCachedCollectionByNameOrId(core.CollectionNameApplicationInstallations)
		signingKey, _ := installations.OAuth2Server.ActiveSigningKey()
		signer, err := signingKey.Signer()
		if err != nil {
			t.Fatal(err)
		}

		otherKey, err := core.NewOAuth2SigningKey(security.JWTAlgRS256)
		if err != nil {
			t.Fatal(err)
		}
		otherSigner, _ := otherKey.Signer()
		otherSigner.Kid = signer.Kid // same kid, another key

		validPayload := func() jwt.MapClaims {
			return jwt.MapClaims{
				"iss":             core.OAuth2Issuer(app, installations),
				"aud":             claims.ClientId,
				"sub":             "staff_id",
				"sid":             "staff_session",
				"installation_id": installed.Installation.Id,
				"extension":       "home",
				"iat":             time.Now().Unix(),
				"jti":             "jti",
			}
		}

		sign := func(payload jwt.MapClaims, s *security.JWTSigner, typ string, duration time.Duration) string {
			var token string
			var err error
			if typ == "" {
				token, err = security.NewSignedJWT(payload, s, duration)
			} else {
				token, err = security.NewSignedJWTWithType(payload, s, duration, typ)
			}
			if err != nil {
				t.Fatal(err)
			}
			return token
		}

		otherIssuer := validPayload()
		otherIssuer["iss"] = "https://evil.example.com/oauth2/_applicationInstallations"

		missingJti := validPayload()
		delete(missingJti, "jti")

		// the A2 install notification JWT is signed with the same issuer key (but without the launch typ)
		notification := sign(jwt.MapClaims{"iss": core.OAuth2Issuer(app, installations), "aud": "ext-app", "event": "application.installed"}, signer, "", time.Minute)

		scenarios := map[string]string{
			"valid control":         sign(validPayload(), signer, core.ApplicationLaunchTokenType, time.Minute),
			"missing typ":           sign(validPayload(), signer, "", time.Minute),
			"other typ":             sign(validPayload(), signer, "JWT", time.Minute),
			"expired":               sign(validPayload(), signer, core.ApplicationLaunchTokenType, -time.Minute),
			"other key (same kid)":  sign(validPayload(), otherSigner, core.ApplicationLaunchTokenType, time.Minute),
			"other issuer":          sign(otherIssuer, signer, core.ApplicationLaunchTokenType, time.Minute),
			"missing jti":           sign(missingJti, signer, core.ApplicationLaunchTokenType, time.Minute),
			"install notification":  notification,
			"auth token (HS256)":    "",
			"malformed":             "abc",
			"empty":                 "",
			"tampered valid":        token[:len(token)-4] + "abcd",
			"valid but other claim": sign(jwt.MapClaims{"iss": core.OAuth2Issuer(app, installations)}, signer, core.ApplicationLaunchTokenType, time.Minute),
		}

		superuser, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
		authToken, err := tests.NewSessionAuthToken(app, superuser)
		if err != nil {
			t.Fatal(err)
		}
		scenarios["auth token (HS256)"] = authToken

		for name, raw := range scenarios {
			_, err := core.ParseApplicationLaunchToken(app, raw)
			if name == "valid control" {
				if err != nil {
					t.Fatalf("[%s] Expected the token to be valid, got %v", name, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("[%s] Expected the launch token to be rejected", name)
			}
		}
	})
}

func TestApplicationLaunchSessionInvariants(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installed := installTestExtensionsApplication(t, app, core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	})

	staff, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	dashboardSession, err := tests.CreateAuthSession(app, staff)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(installed.Client.GrantTypes(), core.OAuth2GrantTypeTokenExchange) {
		t.Fatalf("Expected the managed client to allow the token exchange grant, got %v", installed.Client.GrantTypes())
	}

	newLaunchSession := func(jti string, parent string, client string) *core.AuthSession {
		now := types.NowDateTime()
		session := core.NewAuthSession(app)
		session.Set("status", core.AuthSessionStatusActive)
		session.SetCollectionRef(staff.Collection().Id)
		session.SetClient(client)
		session.SetRecordRef(staff.Id)
		session.SetParent(parent)
		session.SetLaunchJti(jti)
		session.SetScopes([]string{"read_demo2"})
		session.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodLaunch, Time: now}})
		session.SetAuthTime(now)
		session.SetLastUsedAt(now)
		session.SetExpiresAt(now.Add(time.Hour))
		return session
	}

	t.Run("invalid launch sessions", func(t *testing.T) {
		tests.TestValidationErrors(t, app.Save(newLaunchSession("", dashboardSession.Parent(), installed.Client.Id)), []string{"amr"})
		tests.TestValidationErrors(t, app.Save(newLaunchSession("jti1", "", installed.Client.Id)), []string{"amr"})

		// a regular (dashboard) client
		tests.TestValidationErrors(t, app.Save(newLaunchSession("jti2", dashboardSession.Parent(), dashboardSession.Client())), []string{"amr"})

		// a launch jti without the launch method
		noMethod := newLaunchSession("jti3", dashboardSession.Parent(), installed.Client.Id)
		noMethod.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}})
		tests.TestValidationErrors(t, app.Save(noMethod), []string{"amr", "client"})

		// a non-staff actor with the managed client
		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		customer := newLaunchSession("jti4", dashboardSession.Parent(), installed.Client.Id)
		customer.SetCollectionRef(user.Collection().Id)
		customer.SetRecordRef(user.Id)
		tests.TestValidationErrors(t, app.Save(customer), []string{"amr"})
	})

	t.Run("valid launch session, attach and token", func(t *testing.T) {
		session := newLaunchSession("jti_valid", dashboardSession.Parent(), installed.Client.Id)
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		if err := session.AttachActor(staff, installed.Client); err != nil {
			t.Fatalf("Expected the managed client to be attachable to the launch session, got %v", err)
		}

		token, err := session.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected the online token to be valid, got %v", err)
		}

		// the jti is single use (unique)
		if err := app.Save(newLaunchSession("jti_valid", dashboardSession.Parent(), installed.Client.Id)); err == nil {
			t.Fatal("Expected the duplicated launch jti to be rejected")
		}

		// the online sessions require the token_exchange grant of the managed client
		if _, err := app.DB().NewQuery("UPDATE {{_oauth2Clients}} SET [[grantTypes]] = '[\"client_credentials\"]' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Client.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the online token of a client without the token_exchange grant to be rejected")
		}
		if _, err := app.DB().NewQuery("UPDATE {{_oauth2Clients}} SET [[grantTypes]] = '[\"client_credentials\",\"token_exchange\"]' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Client.Id}).Execute(); err != nil {
			t.Fatal(err)
		}

		// pending installation
		if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'pending' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the online token of a pending installation to be rejected")
		}
		if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[status]] = 'active' WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected the online token to be valid again, got %v", err)
		}

		// ending the staff root SSO session (aka. logout) ends the online session
		root, err := app.FindAuthSessionById(dashboardSession.Parent())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.End(); err != nil {
			t.Fatal(err)
		}
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the online token to be rejected after the staff logout")
		}
		fresh, _ := app.FindAuthSessionById(session.Id)
		if fresh.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the online session to be ended with the root, got %q", fresh.Status())
		}

		// the ended online session (and its jti) is kept until the launch token can't be valid anymore
		if err := app.DeleteExpiredAuthSessions(); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthSessionById(session.Id); err != nil {
			t.Fatal("Expected the recently ended online session to be kept (jti replay protection)")
		}
		if _, err := app.DB().NewQuery("UPDATE {{_authSessions}} SET [[created]] = '2000-01-01 00:00:00.000Z' WHERE id = {:id}").
			Bind(map[string]any{"id": session.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		if err := app.DeleteExpiredAuthSessions(); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthSessionById(session.Id); err == nil {
			t.Fatal("Expected the old ended online session to be deleted")
		}
	})
}

func TestAuthorizeOnBehalfOfFailClosed(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installed := installTestExtensionsApplication(t, app, core.Permissions{
		Collections: map[string][]string{demo2.Id: core.PermissionCollectionActions},
		System:      map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead},
	})

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")

	scopes := []string{"read_demo2", "write_demo2", "system:read_logs"}

	scenarios := []struct {
		name           string
		auth           *core.Record
		installationId string
		scopes         []string
		expectView     bool
		expectCreate   bool
		expectLogs     bool
		expectSQL      bool
	}{
		{"Owner online token (= grant ∩ scopes)", owner, installed.Installation.Id, scopes, true, true, true, false},
		{"Owner online token with narrowed scopes", owner, installed.Installation.Id, []string{"read_demo2"}, true, false, false, false},
		{"Owner with a missing installation", owner, "missing", scopes, false, false, false, false},
		{"customer with a managed client token", user, installed.Installation.Id, scopes, false, false, false, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			info := &core.RequestInfo{
				Auth: s.auth,
				OAuth2: core.RequestInfoOAuth2{
					ClientId:                  installed.Client.ClientId(),
					Scopes:                    s.scopes,
					ApplicationInstallationId: s.installationId,
				},
			}

			perms := info.Permissions(app)
			if perms.Owner || !perms.ThirdParty {
				t.Fatalf("Expected a non-Owner third-party actor, got %+v", perms)
			}

			view := info.CollectionAccess(app, demo2, core.PermissionActionView)
			create := info.CollectionAccess(app, demo2, core.PermissionActionCreate)

			if view.Allowed != s.expectView || (s.expectView && !view.BypassRules) {
				t.Fatalf("Expected view %v, got %+v", s.expectView, view)
			}
			if create.Allowed != s.expectCreate {
				t.Fatalf("Expected create %v, got %+v", s.expectCreate, create)
			}
			if v := info.Can(app, core.PermissionResourceLogs, core.PermissionLevelRead); v != s.expectLogs {
				t.Fatalf("Expected logs read %v, got %v", s.expectLogs, v)
			}
			if v := info.Can(app, core.PermissionResourceSQL, core.PermissionLevelWrite); v != s.expectSQL {
				t.Fatalf("Expected sql %v, got %v", s.expectSQL, v)
			}
			if v := info.IsOwner(app); v {
				t.Fatal("Expected the online token to never be an Owner")
			}
		})
	}
}

func TestRequestInfoIsStaffTokenSemantics(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")

	scenarios := []struct {
		name     string
		auth     *core.Record
		oauth2   core.RequestInfoOAuth2
		expected bool
	}{
		{"guest", nil, core.RequestInfoOAuth2{}, false},
		{"customer first-party", user, core.RequestInfoOAuth2{ClientId: "c", FirstParty: true}, false},
		{"staff programmatic (no token data)", owner, core.RequestInfoOAuth2{}, true},
		{"staff first-party token", owner, core.RequestInfoOAuth2{ClientId: core.OAuth2DashboardClientId, FirstParty: true}, true},
		{"staff third-party token", owner, core.RequestInfoOAuth2{ClientId: "c"}, false},
		{"staff online token", owner, core.RequestInfoOAuth2{ClientId: "pbapp_x", ApplicationInstallationId: "x"}, false},
		{"staff online token (forged first-party)", owner, core.RequestInfoOAuth2{ClientId: "pbapp_x", FirstParty: true, ApplicationInstallationId: "x"}, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			info := &core.RequestInfo{Auth: s.auth, OAuth2: s.oauth2}
			if v := info.IsStaff(); v != s.expected {
				t.Fatalf("Expected IsStaff %v, got %v", s.expected, v)
			}
		})
	}
}
