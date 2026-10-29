package apis_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

type ownSessionItem struct {
	Id          string           `json:"id"`
	SSO         bool             `json:"sso"`
	Parent      string           `json:"parent"`
	ClientId    string           `json:"clientId"`
	ClientName  string           `json:"clientName"`
	Current     bool             `json:"current"`
	IP          string           `json:"ip"`
	UserAgent   string           `json:"userAgent"`
	AuthMethods []map[string]any `json:"authMethods"`
	Created     string           `json:"created"`
	LastUsedAt  string           `json:"lastUsedAt"`
	ExpiresAt   string           `json:"expiresAt"`
}

func ownSessionsSetup(t testing.TB) (*tests.TestApp, *core.Record, *core.Record) {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}

	oauth2PrepareIssuer(t, app, "users")

	return app, oauth2FindRecord(t, app, "users", "test@example.com"), oauth2FindRecord(t, app, "users", "test2@example.com")
}

func ownSessionToken(t testing.TB, app core.App, record *core.Record, optScopes ...string) (*core.AuthSession, string) {
	t.Helper()

	scopes := optScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email"} // non-offline
	}

	session, err := tests.CreateAuthSession(app, record, scopes...)
	if err != nil {
		t.Fatal(err)
	}

	token, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	return session, token
}

func listOwnSessions(t testing.TB, b *oauth2Browser, collection string, token string) (*http.Response, string, []ownSessionItem) {
	t.Helper()

	res, body := b.do(http.MethodGet, "/api/collections/"+collection+"/sessions", "", map[string]string{"Authorization": token})

	items := []ownSessionItem{}
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &items); err != nil {
			t.Fatal(err)
		}
	}

	return res, body, items
}

func TestRecordAuthSessionsList(t *testing.T) {
	t.Parallel()

	app, userA, userB := ownSessionsSetup(t)
	defer app.Cleanup()

	current, tokenA := ownSessionToken(t, app, userA)
	other, _ := ownSessionToken(t, app, userA)
	otherB, tokenB := ownSessionToken(t, app, userB)

	// an ended client session (not listed; its root SSO session is still active)
	ended, _ := ownSessionToken(t, app, userA)
	if err := app.EndAuthSession(ended, "test"); err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)

	res, body, items := listOwnSessions(t, b, "users", tokenA)
	b.expectStatus(res, body, http.StatusOK)

	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.Id)
	}

	expected := []string{current.Id, current.Parent(), other.Id, other.Parent(), ended.Parent()}
	if len(ids) != len(expected) {
		t.Fatalf("Expected sessions %v, got %v", expected, ids)
	}
	for _, id := range expected {
		if !slices.Contains(ids, id) {
			t.Fatalf("Missing own session %q in %v", id, ids)
		}
	}

	for _, id := range []string{otherB.Id, otherB.Parent(), ended.Id} {
		if slices.Contains(ids, id) {
			t.Fatalf("Unexpected session %q (another record or ended)", id)
		}
	}

	for _, item := range items {
		isCurrent := item.Id == current.Id || item.Id == current.Parent()
		if item.Current != isCurrent {
			t.Fatalf("Expected current=%v for %q", isCurrent, item.Id)
		}

		if item.SSO {
			if item.ClientId != "" || item.Parent != "" {
				t.Fatalf("Unexpected root session client/parent %+v", item)
			}
		} else {
			if item.ClientId != tests.ClientIdForCollection("users") || item.ClientName == "" || item.Parent == "" {
				t.Fatalf("Expected the client session client data %+v", item)
			}
		}

		if len(item.AuthMethods) == 0 || item.AuthMethods[0]["method"] != core.AuthSessionMethodPassword {
			t.Fatalf("Expected the auth methods %+v", item.AuthMethods)
		}
		if item.Created == "" || item.ExpiresAt == "" {
			t.Fatalf("Expected the session dates %+v", item)
		}
	}

	// no secret (or other internal) session fields are exported
	sessionsCollection, err := app.FindCachedCollectionByNameOrId(core.CollectionNameAuthSessions)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append(core.SecretFieldNames(sessionsCollection), "codeChallenge", "nonce", "redirectURI", "impersonatorSession") {
		if strings.Contains(body, `"`+name+`"`) {
			t.Fatalf("Unexpected exported session field %q:\n%s", name, body)
		}
	}

	// user B sees only its own sessions
	res, body, items = listOwnSessions(t, b, "users", tokenB)
	b.expectStatus(res, body, http.StatusOK)
	if len(items) != 2 {
		t.Fatalf("Expected 2 sessions of user B, got %v", items)
	}
	for _, item := range items {
		if item.Id != otherB.Id && item.Id != otherB.Parent() {
			t.Fatalf("Unexpected session of user B %q", item.Id)
		}
	}
}

func TestRecordAuthSessionsAccess(t *testing.T) {
	t.Parallel()

	app, userA, _ := ownSessionsSetup(t)
	defer app.Cleanup()

	_, tokenA := ownSessionToken(t, app, userA)

	// third-party token (same rule as the consents: not allowed)
	thirdParty := oauth2StubClient(t, app, "users", "3p")
	thirdPartyToken, _ := oauth2AccessToken(t, app, thirdParty, userA, []string{"openid", "email"})

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, superuserToken := ownSessionToken(t, app, superuser)

	b := newOAuth2Browser(t, app)

	scenarios := []struct {
		name       string
		collection string
		token      string
		status     int
	}{
		{"guest", "users", "", http.StatusUnauthorized},
		{"third-party token", "users", thirdPartyToken, http.StatusForbidden},
		{"token of another auth collection", "clients", tokenA, http.StatusForbidden},
		{"superuser token on the users path", "users", superuserToken, http.StatusForbidden},
		{"not an auth collection", "demo1", tokenA, http.StatusForbidden},
		{"first-party own token", "users", tokenA, http.StatusOK},
		{"superuser own sessions", core.CollectionNameSuperusers, superuserToken, http.StatusOK},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			headers := map[string]string{}
			if s.token != "" {
				headers["Authorization"] = s.token
			}

			res, body := b.do(http.MethodGet, "/api/collections/"+s.collection+"/sessions", "", headers)
			b.expectStatus(res, body, s.status)

			res, body = b.do(http.MethodPost, "/api/collections/"+s.collection+"/sessions/missing/end", "", headers)
			endStatus := s.status
			if endStatus == http.StatusOK {
				endStatus = http.StatusNotFound
			}
			b.expectStatus(res, body, endStatus)
		})
	}
}

func TestRecordAuthSessionEnd(t *testing.T) {
	t.Parallel()

	app, userA, userB := ownSessionsSetup(t)
	defer app.Cleanup()

	current, tokenA := ownSessionToken(t, app, userA)
	other, otherToken := ownSessionToken(t, app, userA)
	sessionB, tokenB := ownSessionToken(t, app, userB)

	// an offline_access child of the "other" root (survives the root end, the existing cascade semantics)
	offline, err := app.CreateAuthSession(userA, oauth2FindClient(t, app, tests.ClientIdForCollection("users")), core.AuthSessionOptions{
		Scopes:      []string{"openid", "offline_access"},
		Parent:      other.Parent(),
		AuthMethods: other.AuthMethods(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// an impersonation session of user A (an activity of the impersonator, managed only by the staff)
	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	staffSession, _ := ownSessionToken(t, app, superuser)
	impersonation, err := app.CreateAuthSession(userA, oauth2FindClient(t, app, tests.ClientIdForCollection("users")), core.AuthSessionOptions{
		Scopes:              []string{"openid"},
		Impersonator:        superuser.Id,
		ImpersonatorSession: staffSession.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)
	end := func(token string, id string) (*http.Response, string) {
		return b.do(http.MethodPost, "/api/collections/users/sessions/"+id+"/end", "", map[string]string{"Authorization": token})
	}

	// another record sessions can't be ended (reported as not found)
	for _, id := range []string{sessionB.Id, sessionB.Parent()} {
		res, body := end(tokenA, id)
		b.expectStatus(res, body, http.StatusNotFound)
	}
	if !oauth2ReloadSession(t, app, sessionB.Id).IsActive() {
		t.Fatal("Expected the user B session to remain active")
	}
	res, body := b.do(http.MethodGet, "/api/permissions/me", "", map[string]string{"Authorization": tokenB})
	b.expectStatus(res, body, http.StatusOK)

	res, body = end(tokenA, impersonation.Id)
	b.expectStatus(res, body, http.StatusNotFound)
	if !oauth2ReloadSession(t, app, impersonation.Id).IsActive() {
		t.Fatal("Expected the impersonation session to remain active")
	}

	// ending the other root SSO session cascades to its (non-offline) child
	res, body = end(tokenA, other.Parent())
	b.expectStatus(res, body, http.StatusNoContent)
	if oauth2ReloadSession(t, app, other.Parent()).Status() != core.AuthSessionStatusEnded ||
		oauth2ReloadSession(t, app, other.Id).Status() != core.AuthSessionStatusEnded {
		t.Fatal("Expected the root and its child session to be ended")
	}
	res, body = b.do(http.MethodGet, "/api/permissions/me", "", map[string]string{"Authorization": otherToken})
	b.expectStatus(res, body, http.StatusUnauthorized)
	if !oauth2ReloadSession(t, app, offline.Id).IsActive() {
		t.Fatal("Expected the offline_access child to survive the root end")
	}

	// the current session still works (+ the offline session)
	res, body, items := listOwnSessions(t, b, "users", tokenA)
	b.expectStatus(res, body, http.StatusOK)
	if len(items) != 3 {
		t.Fatalf("Expected the current root and child and the offline session, got %v", items)
	}

	// the offline client session could be ended directly
	res, body = end(tokenA, offline.Id)
	b.expectStatus(res, body, http.StatusNoContent)
	if oauth2ReloadSession(t, app, offline.Id).Status() != core.AuthSessionStatusEnded {
		t.Fatal("Expected the offline session to be ended")
	}

	// ending the current root = logout of that SSO session
	res, body = end(tokenA, current.Parent())
	b.expectStatus(res, body, http.StatusNoContent)
	res, body = b.do(http.MethodGet, "/api/collections/users/sessions", "", map[string]string{"Authorization": tokenA})
	b.expectStatus(res, body, http.StatusUnauthorized)

	if !oauth2ReloadSession(t, app, sessionB.Id).IsActive() {
		t.Fatal("Expected the user B session to remain active")
	}
}
