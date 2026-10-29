package apis_test

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/subscriptions"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
	"golang.org/x/oauth2"
)

const oauth2FakeProviderName = "o1fake"

// oauth2FakeUpstream is a fake upstream OAuth2 provider token endpoint
// (the issued access token is the exchanged code).
type oauth2FakeUpstream struct {
	server *httptest.Server

	mu        sync.Mutex
	exchanges map[string]url.Values // code -> token request form
	users     map[string]*auth.AuthUser
}

var oauth2FakeUpstreamInstance = sync.OnceValue(func() *oauth2FakeUpstream {
	u := &oauth2FakeUpstream{
		exchanges: map[string]url.Values{},
		users:     map[string]*auth.AuthUser{},
	}

	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}

		code := r.PostForm.Get("code")

		u.mu.Lock()
		u.exchanges[code] = r.PostForm
		_, ok := u.users[code]
		u.mu.Unlock()

		if !ok {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		raw, _ := json.Marshal(map[string]any{"access_token": code, "token_type": "bearer"})
		w.Write(raw)
	}))

	return u
})

func (u *oauth2FakeUpstream) stubUser(code string, user *auth.AuthUser) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.users[code] = user
}

func (u *oauth2FakeUpstream) exchange(code string) url.Values {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.exchanges[code]
}

type oauth2FakeProvider struct {
	auth.BaseProvider
}

func (p *oauth2FakeProvider) FetchAuthUser(token *oauth2.Token) (*auth.AuthUser, error) {
	u := oauth2FakeUpstreamInstance()

	u.mu.Lock()
	defer u.mu.Unlock()

	user, ok := u.users[token.AccessToken]
	if !ok {
		return nil, errors.New("unknown fake user")
	}

	clone := *user

	return &clone, nil
}

func init() {
	// registered once to avoid concurrent writes of the global providers map
	auth.Providers[oauth2FakeProviderName] = func() auth.Provider {
		p := &oauth2FakeProvider{}
		p.SetDisplayName("Fake")
		p.SetPKCE(true)
		p.SetAuthURL("https://fake.example.com/authorize")
		p.SetTokenURL(oauth2FakeUpstreamInstance().server.URL + "/token")
		return p
	}
}

func oauth2EnableFakeProvider(c *core.Collection) {
	c.OAuth2.Enabled = true
	c.OAuth2.MappedFields.Name = "name"
	c.OAuth2.Providers = []core.OAuth2ProviderConfig{{
		Name:         oauth2FakeProviderName,
		ClientId:     "fake_client",
		ClientSecret: "fake_secret",
	}}
}

// oauth2StartUpstream opens the fake provider link from the current login page and returns the upstream state and challenge.
func oauth2StartUpstream(t testing.TB, b *oauth2Browser) (state string, challenge string) {
	t.Helper()

	link := hrefLink(b.lastHTML, "/login/oauth2/"+oauth2FakeProviderName)
	if link == "" {
		t.Fatalf("Missing fake provider link:\n%s", b.lastHTML)
	}

	res, _ := b.get(link)
	b.expectStatus(res, "", http.StatusFound)

	query := oauth2ExpectRedirect(t, res, "https://fake.example.com/authorize?", map[string]string{
		"state":                 "*",
		"code_challenge":        "*",
		"code_challenge_method": "S256",
		"client_id":             "fake_client",
		"redirect_uri":          "http://localhost:8090/api/oauth2-redirect",
	})

	if !strings.HasPrefix(query.Get("state"), "pbas.") {
		t.Fatalf("Expected hosted flow upstream state, got %q", query.Get("state"))
	}

	return query.Get("state"), query.Get("code_challenge")
}

func TestOAuth2ServerUpstreamOAuth2(t *testing.T) {
	t.Parallel()

	upstream := oauth2FakeUpstreamInstance()

	t.Run("GET callback (new record)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		code := "get_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{Id: "fake_new", Email: "upstream_new@example.com", Name: "Upstream New"})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		session := b.sessionByHandle(handle)

		state, challenge := oauth2StartUpstream(t, b)

		if s := oauth2ReloadSession(t, app, session.Id); s.UpstreamProvider() != oauth2FakeProviderName || s.UpstreamCodeVerifier() == "" {
			t.Fatal("Expected stored upstream step data")
		}

		res, _ := b.get("/api/oauth2-redirect?code=" + code + "&state=" + url.QueryEscape(state))
		b.expectStatus(res, "", http.StatusFound)
		query := oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/continue?", map[string]string{"auth_state": "*"})

		// the handle is rotated
		if query.Get("auth_state") == handle {
			t.Fatal("Expected rotated handle")
		}
		if res, _ := b.get("/oauth2/users/login?auth_state=" + handle); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected the old handle to be invalid, got %d", res.StatusCode)
		}

		// server-side code exchange with PKCE
		exchange := upstream.exchange(code)
		if exchange == nil || security.S256Challenge(exchange.Get("code_verifier")) != challenge || exchange.Get("redirect_uri") != "http://localhost:8090/api/oauth2-redirect" {
			t.Fatalf("Unexpected upstream exchange %v", exchange)
		}

		// the upstream state is single use
		replayed, body := b.get("/api/oauth2-redirect?code=" + code + "&state=" + url.QueryEscape(state))
		if replayed.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected replayed state to fail, got %d %s", replayed.StatusCode, body)
		}

		res, _ = b.follow(res)
		authCode := b.expectCode(res, oauth2TestIssuer)

		record := oauth2FindRecord(t, app, "users", "upstream_new@example.com")
		if !record.Verified() || record.GetString("name") != "Upstream New" {
			t.Fatalf("Expected verified record with mapped name, got %v", record.PublicExport())
		}

		ea, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{"provider": oauth2FakeProviderName, "providerId": "fake_new"})
		if err != nil || ea.RecordRef() != record.Id {
			t.Fatalf("Expected linked external auth, got %v", err)
		}

		s := b.sessionByCode(authCode)
		methods := s.AuthMethods()
		if s.RecordRef() != record.Id || len(methods) != 1 || methods[0].Method != core.AuthSessionMethodOAuth2 || methods[0].Provider != oauth2FakeProviderName {
			t.Fatalf("Unexpected session actor/amr %q %v", s.RecordRef(), methods)
		}
		if s.UpstreamProvider() != "" || s.UpstreamCodeVerifier() != "" {
			t.Fatal("Expected the upstream data to be cleared")
		}
	})

	t.Run("form_post callback (existing record by email)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		existing := oauth2FindRecord(t, app, "users", "test2@example.com")

		code := "post_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{Id: "fake_existing", Email: existing.Email()})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		state, _ := oauth2StartUpstream(t, b)

		// cross-site POST without cookies (e.g. Apple form_post)
		crossSite := b.clone(false)
		form := url.Values{}
		form.Set("code", code)
		form.Set("state", state)
		form.Set("user", `{"name":{"firstName":"Apple","lastName":"User"}}`)
		res, body := crossSite.do(http.MethodPost, "/api/oauth2-redirect", form.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Origin":       "https://appleid.apple.com",
		})
		crossSite.expectStatus(res, body, http.StatusSeeOther)
		continueURL := res.Header.Get("Location")
		if !strings.HasPrefix(continueURL, oauth2TestPages+"/login/continue?auth_state=") {
			t.Fatalf("Expected continue redirect, got %q", continueURL)
		}

		// only the browser with the binding cookie could continue
		res, body = crossSite.get(continueURL)
		crossSite.expectStatus(res, body, http.StatusBadRequest)

		res, _ = b.get(continueURL)
		authCode := b.expectCode(res, oauth2TestIssuer)

		if s := b.sessionByCode(authCode); s.RecordRef() != existing.Id {
			t.Fatalf("Expected the existing record actor, got %q", s.RecordRef())
		}

		ea, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{"provider": oauth2FakeProviderName, "providerId": "fake_existing"})
		if err != nil || ea.RecordRef() != existing.Id {
			t.Fatalf("Expected the provider to be linked to the existing record, got %v", err)
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		state, _ := oauth2StartUpstream(t, b)

		res, _ := b.get("/api/oauth2-redirect?error=access_denied&state=" + url.QueryEscape(state))
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"auth_state": "*", "error": "upstream"})

		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "Failed to sign in with the selected provider.") {
			t.Fatalf("Expected upstream error message:\n%s", body)
		}

		// the flow could continue with another method
		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
	})

	t.Run("failed code exchange", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		state, _ := oauth2StartUpstream(t, b)

		res, _ := b.get("/api/oauth2-redirect?code=unknown_code&state=" + url.QueryEscape(state))
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"error": "upstream"})
	})

	t.Run("invalid upstream state", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		state, _ := oauth2StartUpstream(t, b)

		session := b.sessionByHandle(handle)

		for _, forged := range []string{
			"pbas.",
			"pbas.missing.secret",
			"pbas." + session.Id + ".wrong_secret",
			"pbas." + session.Id,
		} {
			res, body := b.get("/api/oauth2-redirect?code=abc&state=" + url.QueryEscape(forged))
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("[%s] Expected 400, got %d %s", forged, res.StatusCode, body)
			}
		}

		// the valid state was not consumed by the forged attempts
		if s := oauth2ReloadSession(t, app, session.Id); s.UpstreamProvider() == "" || !strings.HasPrefix(state, "pbas."+session.Id+".") {
			t.Fatal("Expected the upstream step to remain pending")
		}
	})

	t.Run("MFA second factor of another record", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider, oauth2EnableMFA(""))

		code := "mfa_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{Id: "fake_attacker", Email: "attacker@example.com"})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		b.follow(res)

		state, _ := oauth2StartUpstream(t, b)
		res, _ = b.get("/api/oauth2-redirect?code=" + code + "&state=" + url.QueryEscape(state))
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", map[string]string{"error": "upstream"})

		// no new record and no link to the identified record (aka. no MFA bypass)
		if _, err := app.FindAuthRecordByEmail("users", "attacker@example.com"); err == nil {
			t.Fatal("Expected no created record")
		}
		if _, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{"providerId": "fake_attacker"}); err == nil {
			t.Fatal("Expected no linked external auth")
		}

		session := b.sessionByHandle(hiddenFieldFromLocation(t, res))
		if len(session.AuthMethods()) != 1 || handle == "" {
			t.Fatalf("Expected only the first factor, got %v", session.AuthMethods())
		}
	})
}

func hiddenFieldFromLocation(t testing.TB, res *http.Response) string {
	t.Helper()

	u, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	return u.Query().Get("auth_state")
}

func TestOAuth2ServerUpstreamFactorAppliedOnlyAfterBindingCheck(t *testing.T) {
	t.Parallel()

	upstream := oauth2FakeUpstreamInstance()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)
	oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

	existing := oauth2FindRecord(t, app, "users", "test2@example.com")

	code := "binding_" + security.RandomString(10)
	upstream.stubUser(code, &auth.AuthUser{Id: "fake_binding", Email: existing.Email()})

	b := newOAuth2Browser(t, app)
	handle := b.startLogin("users", "app", nil)
	session := b.sessionByHandle(handle)
	state, _ := oauth2StartUpstream(t, b)

	// the callback alone (cross-site, without cookies) only stores the pending result
	crossSite := b.clone(false)
	res, _ := crossSite.get("/api/oauth2-redirect?code=" + code + "&state=" + url.QueryEscape(state))
	crossSite.expectStatus(res, "", http.StatusFound)
	continueURL := res.Header.Get("Location")

	pending := oauth2ReloadSession(t, app, session.Id)
	if pending.RecordRef() != "" || len(pending.AuthMethods()) != 0 {
		t.Fatalf("Expected the callback alone to not identify the actor, got %q %v", pending.RecordRef(), pending.AuthMethods())
	}
	if pending.UpstreamRecordRef() != existing.Id || pending.UpstreamProvider() != oauth2FakeProviderName {
		t.Fatalf("Expected pending upstream result, got %q %q", pending.UpstreamRecordRef(), pending.UpstreamProvider())
	}

	// continue from a foreign browser (no binding cookie) fails and doesn't identify
	res, body := crossSite.get(continueURL)
	crossSite.expectStatus(res, body, http.StatusBadRequest)

	foreign := newOAuth2Browser(t, app)
	foreign.startLogin("users", "app", nil) // with its own binding cookie of another flow
	res, body = foreign.get(continueURL)
	foreign.expectStatus(res, body, http.StatusBadRequest)

	if s := oauth2ReloadSession(t, app, session.Id); s.RecordRef() != "" || len(s.AuthMethods()) != 0 || s.UpstreamRecordRef() == "" {
		t.Fatalf("Expected the session to remain unidentified with pending result, got %q %v", s.RecordRef(), s.AuthMethods())
	}

	// the browser with the binding cookie applies the factor
	res, _ = b.get(continueURL)
	authCode := b.expectCode(res, oauth2TestIssuer)

	s := b.sessionByCode(authCode)
	if s.RecordRef() != existing.Id || !s.HasAuthMethod(core.AuthSessionMethodOAuth2) || s.UpstreamRecordRef() != "" || s.UpstreamProvider() != "" {
		t.Fatalf("Expected identified session with cleared pending result, got %q %v", s.RecordRef(), s.AuthMethods())
	}
}

func TestOAuth2RedirectRealtimeModeRemoved(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// a realtime client that previously used the "@oauth2" subscription mode
	client := subscriptions.NewDefaultClient()
	client.Subscribe("@oauth2")
	app.SubscriptionsBroker().Register(client)

	b := newOAuth2Browser(t, app)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var res *http.Response
		if method == http.MethodGet {
			res, _ = b.get("/api/oauth2-redirect?state=" + url.QueryEscape(client.Id()) + "&code=123")
		} else {
			res, _ = b.post("/api/oauth2-redirect", oauth2URLValues(map[string]string{"state": client.Id(), "code": "123"}))
		}

		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("[%s] Expected 400 for non hosted flow state, got %d", method, res.StatusCode)
		}
	}

	select {
	case msg := <-client.Channel():
		t.Fatalf("Expected no realtime message, got %v", msg)
	case <-time.After(50 * time.Millisecond):
	}
}
