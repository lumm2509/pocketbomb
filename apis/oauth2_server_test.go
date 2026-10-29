package apis_test

import (
	"encoding/json/v2"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/dbx"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

const (
	oauth2TestIssuer       = "http://localhost:8090/oauth2/users"
	oauth2TestPages        = "/oauth2/users" // same-origin hosted pages base path
	oauth2TestRedirectURI  = "https://example.com/callback"
	oauth2TestLogoutURI    = "https://example.com/logout"
	oauth2TestCodeVerifier = "test_code_verifier_0123456789_0123456789_abcdefghij"
	oauth2TestCSRF         = "0123456789abcdefghij0123456789ab"
	oauth2TestOrigin       = "http://localhost:8090"
)

var oauth2TestCodeChallenge = security.S256Challenge(oauth2TestCodeVerifier)

// oauth2TestSigningKey is a shared ES256 key to avoid the
// (slow) RSA key generation for each test scenario.
var oauth2TestSigningKey = sync.OnceValue(func() core.OAuth2SigningKey {
	key, err := core.NewOAuth2SigningKey(security.JWTAlgES256)
	if err != nil {
		panic(err)
	}
	return key
})

// oauth2PrepareIssuer prepares the specified auth collection issuer for the tests
// (custom "posts:read" scope, shared ES256 signing key and disabled MFA).
//
// Note that every auth collection is an issuer and this helper only normalizes the test data.
func oauth2PrepareIssuer(t testing.TB, app core.App, collectionName string, modifiers ...func(c *core.Collection)) *core.Collection {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(collectionName)
	if err != nil {
		t.Fatal(err)
	}

	collection.OAuth2Server.Scopes = []string{"posts:read"}
	collection.OAuth2Server.SigningKeys = []core.OAuth2SigningKey{oauth2TestSigningKey()}
	collection.MFA.Enabled = false

	for _, m := range modifiers {
		m(collection)
	}

	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	return collection
}

func oauth2Confidential(c *core.OAuth2Client) {
	c.SetType(core.OAuth2ClientTypeConfidential)
	c.SetClientSecret("secret_" + c.ClientId())
}

func oauth2FirstParty(c *core.OAuth2Client) {
	c.SetFirstParty(true)
}

// oauth2StubClient creates a new public OAuth2 client for the specified collection.
func oauth2StubClient(t testing.TB, app core.App, collectionName string, clientId string, modifiers ...func(c *core.OAuth2Client)) *core.OAuth2Client {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(collectionName)
	if err != nil {
		t.Fatal(err)
	}

	client := core.NewOAuth2Client(app)
	client.SetName("Test App " + clientId)
	client.SetClientId(clientId)
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetCollectionRef(collection.Id)
	client.SetRedirectURIs([]string{oauth2TestRedirectURI})
	client.SetPostLogoutRedirectURIs([]string{oauth2TestLogoutURI})
	client.SetScopes([]string{"openid", "email", "profile", "offline_access", "posts:read"})

	for _, m := range modifiers {
		m(client)
	}

	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	return client
}

func oauth2FindRecord(t testing.TB, app core.App, collectionName string, email string) *core.Record {
	t.Helper()

	record, err := app.FindAuthRecordByEmail(collectionName, email)
	if err != nil {
		t.Fatal(err)
	}

	return record
}

func oauth2FindClient(t testing.TB, app core.App, clientId string) *core.OAuth2Client {
	t.Helper()

	client, err := app.FindOAuth2ClientByClientId(clientId)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func oauth2ReloadSession(t testing.TB, app core.App, id string) *core.AuthSession {
	t.Helper()

	session, err := app.FindAuthSessionById(id)
	if err != nil {
		t.Fatal(err)
	}

	return session
}

// oauth2AccessToken creates a new active auth session and returns a new access token for it.
func oauth2AccessToken(t testing.TB, app core.App, client *core.OAuth2Client, record *core.Record, scopes []string) (string, *core.AuthSession) {
	t.Helper()

	session, err := app.CreateAuthSession(record, client, core.AuthSessionOptions{
		Scopes:      scopes,
		AuthMethods: []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}},
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	return token, session
}

// oauth2StubAuthorizedSession creates a new authorized auth session with the provided plain authorization code
// (aka. the state right before the code exchange).
func oauth2StubAuthorizedSession(t testing.TB, app core.App, client *core.OAuth2Client, record *core.Record, plainCode string, scopes []string, modifiers ...func(s *core.AuthSession)) *core.AuthSession {
	t.Helper()

	session := core.NewAuthSession(app)
	session.SetCollectionRef(record.Collection().Id)
	session.SetClient(client.Id)
	session.SetRecordRef(record.Id)
	session.SetRedirectURI(oauth2TestRedirectURI)
	session.SetCodeChallenge(oauth2TestCodeChallenge, "S256")
	session.SetNonce("test_nonce")
	session.SetState("test_state")
	session.SetScopesRequested(scopes)
	session.SetScopes(scopes)
	session.AddAuthMethod(core.AuthSessionMethodPassword, "")
	session.SetExpiresAt(types.NowDateTime().Add(time.Hour))
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}

	// note: each transition must be persisted (skipping steps is not allowed)
	if err := session.MarkAuthenticated(); err != nil {
		t.Fatal(err)
	}
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	if err := session.MarkAuthorized(); err != nil {
		t.Fatal(err)
	}
	session.SetCode(plainCode, types.NowDateTime().Add(time.Minute))

	for _, m := range modifiers {
		m(session)
	}

	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}

	return session
}

// oauth2StubRefreshSession creates a new active auth session with the provided plain refresh token.
func oauth2StubRefreshSession(t testing.TB, app core.App, client *core.OAuth2Client, record *core.Record, scopes []string, refreshToken string) *core.AuthSession {
	t.Helper()

	session, err := app.CreateAuthSession(record, client, core.AuthSessionOptions{Scopes: scopes, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	session.SetRefreshToken(refreshToken)
	session.SetRefreshExpiresAt(types.NowDateTime().Add(time.Hour))
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}

	return session
}

// oauth2StubSSO creates a new root SSO session (without client) for the specified record and returns its "pb_session" cookie.
func oauth2StubSSO(t testing.TB, app core.App, record *core.Record, authTime types.DateTime) (string, *core.AuthSession) {
	t.Helper()

	secret := security.RandomString(40)

	root := core.NewAuthSession(app)
	root.Set("status", core.AuthSessionStatusActive)
	root.SetCollectionRef(record.Collection().Id)
	root.SetRecordRef(record.Id)
	root.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: authTime}})
	root.SetAuthTime(authTime)
	root.SetSSOSecret(secret)
	root.SetExpiresAt(types.NowDateTime().Add(time.Hour))
	if err := app.Save(root); err != nil {
		t.Fatal(err)
	}

	return "pb_session=" + root.Id + "." + secret, root
}

// oauth2AuthorizeURL returns an authorization endpoint url with
// default params that could be modified via the "params" map
// (empty value means that the param will be removed).
func oauth2AuthorizeURL(collectionName string, clientId string, params map[string]string) string {
	values := url.Values{}
	values.Set("client_id", clientId)
	values.Set("redirect_uri", oauth2TestRedirectURI)
	values.Set("response_type", "code")
	values.Set("scope", "openid email")
	values.Set("state", "test_state")
	values.Set("nonce", "test_nonce")
	values.Set("code_challenge", oauth2TestCodeChallenge)
	values.Set("code_challenge_method", "S256")

	for k, v := range params {
		if v == "" {
			values.Del(k)
		} else {
			values.Set(k, v)
		}
	}

	return "/oauth2/" + collectionName + "/authorize?" + values.Encode()
}

// oauth2ExpectRedirect checks whether the response is a redirect to
// the expected url prefix and with the expected query params
// ("*" means any non-empty value and "" - missing param).
func oauth2ExpectRedirect(t testing.TB, res *http.Response, expectedPrefix string, expectedParams map[string]string) url.Values {
	t.Helper()

	location := res.Header.Get("Location")
	if !strings.HasPrefix(location, expectedPrefix) {
		t.Fatalf("Expected Location with prefix %q, got %q", expectedPrefix, location)
	}

	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	query := u.Query()
	for k, v := range expectedParams {
		if v == "*" {
			if query.Get(k) == "" {
				t.Fatalf("Expected non-empty %q redirect param, got %q", k, location)
			}
			continue
		}

		if query.Get(k) != v {
			t.Fatalf("Expected %q redirect param %q, got %q (%s)", k, v, query.Get(k), location)
		}
	}

	return query
}

func oauth2Form(values map[string]string) string {
	form := url.Values{}
	for k, v := range values {
		form.Set(k, v)
	}
	return form.Encode()
}

// -------------------------------------------------------------------

func TestOAuth2ServerDiscovery(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:           "every auth collection is an issuer (fixture key)",
			Method:         http.MethodGet,
			URL:            "/oauth2/users/.well-known/openid-configuration",
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"` + oauth2TestIssuer + `"`,
				`"id_token_signing_alg_values_supported":["RS256"]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "non-auth collection",
			Method:          http.MethodGet,
			URL:             "/oauth2/demo1/.well-known/openid-configuration",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "collection referenced by id instead of name",
			Method: http.MethodGet,
			URL:    "/oauth2/_pb_users_auth_/.well-known/openid-configuration",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "issuer openid-configuration",
			Method: http.MethodGet,
			URL:    "/oauth2/users/.well-known/openid-configuration",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"` + oauth2TestIssuer + `"`,
				`"authorization_endpoint":"` + oauth2TestIssuer + `/authorize"`,
				`"token_endpoint":"` + oauth2TestIssuer + `/token"`,
				`"userinfo_endpoint":"` + oauth2TestIssuer + `/userinfo"`,
				`"jwks_uri":"` + oauth2TestIssuer + `/jwks.json"`,
				`"revocation_endpoint":"` + oauth2TestIssuer + `/revoke"`,
				`"introspection_endpoint":"` + oauth2TestIssuer + `/introspect"`,
				`"end_session_endpoint":"` + oauth2TestIssuer + `/logout"`,
				`"scopes_supported":["openid","email","profile","offline_access","posts:read","read_users","write_users",`,
				`"response_types_supported":["code"]`,
				`"response_modes_supported":["query"]`,
				`"grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:token-exchange"]`,
				`"code_challenge_methods_supported":["S256"]`,
				`"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]`,
				`"id_token_signing_alg_values_supported":["ES256"]`,
				`"subject_types_supported":["public"]`,
				`"claims_supported":[`,
				`"authorization_response_iss_parameter_supported":true`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "issuer oauth-authorization-server",
			Method: http.MethodGet,
			URL:    "/oauth2/users/.well-known/oauth-authorization-server",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"` + oauth2TestIssuer + `"`,
				`"authorization_response_iss_parameter_supported":true`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "_superusers issuer",
			Method: http.MethodGet,
			URL:    "/oauth2/_superusers/.well-known/openid-configuration",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"http://localhost:8090/oauth2/_superusers"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestOAuth2ServerJWKS(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "non-auth collection",
			Method:          http.MethodGet,
			URL:             "/oauth2/demo1/jwks.json",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "issuer with active and inactive keys",
			Method: http.MethodGet,
			URL:    "/oauth2/users/jwks.json",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
					inactive := oauth2TestSigningKey()
					inactive.Kid = "inactive_kid"
					inactive.Active = false
					c.OAuth2Server.SigningKeys = append(c.OAuth2Server.SigningKeys, inactive)
				})
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"keys":[`,
				`"kid":"` + oauth2TestSigningKey().Kid + `"`,
				`"kid":"inactive_kid"`,
				`"kty":"EC"`,
				`"crv":"P-256"`,
				`"use":"sig"`,
			},
			NotExpectedContent: []string{
				"PRIVATE KEY",
				`"d":`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestOAuth2ServerRootWellKnown(t *testing.T) {
	t.Parallel()

	setDefault := func(t testing.TB, app *tests.TestApp, collection string) {
		app.Settings().OAuth2Server.DefaultCollection = collection
		if err := app.Save(app.Settings()); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "openid-configuration without default collection",
			Method:          http.MethodGet,
			URL:             "/.well-known/openid-configuration",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},

		{
			Name:   "openid-configuration with default collection",
			Method: http.MethodGet,
			URL:    "/.well-known/openid-configuration",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
				setDefault(t, app, "users")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"` + oauth2TestIssuer + `"`,
				`"token_endpoint":"` + oauth2TestIssuer + `/token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "oauth-authorization-server with default collection",
			Method: http.MethodGet,
			URL:    "/.well-known/oauth-authorization-server",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
				setDefault(t, app, "users")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"issuer":"` + oauth2TestIssuer + `"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "oauth-protected-resource without default collection",
			Method:          http.MethodGet,
			URL:             "/.well-known/oauth-protected-resource",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "oauth-protected-resource with default collection",
			Method: http.MethodGet,
			URL:    "/.well-known/oauth-protected-resource",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
				setDefault(t, app, "users")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"resource":"http://localhost:8090"`,
				`"authorization_servers":["` + oauth2TestIssuer + `"]`,
				`"bearer_methods_supported":["header"]`,
				`"scopes_supported":["openid","email","profile","offline_access","posts:read","read_users","write_users",`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

// oauth2TestMux is a minimal router wrapper used for the multi-step flow tests.
type oauth2TestMux struct {
	t       testing.TB
	app     core.App
	handler http.Handler
}

func oauth2Mux(t testing.TB, app core.App) *oauth2TestMux {
	t.Helper()

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}

	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	return &oauth2TestMux{t: t, app: app, handler: mux}
}

func (m *oauth2TestMux) do(method string, rawURL string, body io.Reader, headers map[string]string) *http.Response {
	m.t.Helper()

	// resolve the token placeholders (see tests.AuthToken)
	cache := map[string]string{}
	rawURL = oauth2ResolvePlaceholders(m.t, m.app, rawURL, cache)

	req := httptest.NewRequest(method, rawURL, body)
	for k, v := range headers {
		req.Header.Set(k, oauth2ResolvePlaceholders(m.t, m.app, v, cache))
	}

	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)

	return rec.Result()
}

func oauth2FormHeaders(extra map[string]string) map[string]string {
	result := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range extra {
		result[k] = v
	}
	return result
}

// oauth2SidlessToken returns a signed auth token of the provided record but without auth session.
func oauth2SidlessToken(t testing.TB, record *core.Record) string {
	t.Helper()

	token, err := security.NewJWT(jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypeAuth,
		core.TokenClaimId:           record.Id,
		core.TokenClaimCollectionId: record.Collection().Id,
	}, record.TokenKey()+record.Collection().AuthToken.Secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

// oauth2ResolvePlaceholders resolves the token placeholders of the provided string (see tests.AuthToken).
func oauth2ResolvePlaceholders(t testing.TB, app core.App, str string, cache map[string]string) string {
	t.Helper()

	resolved, err := tests.ResolveTokenPlaceholders(app, str, cache)
	if err != nil {
		t.Fatal(err)
	}

	return resolved
}

// oauth2Browser is a minimal browser-like client with a cookie jar used
// for the hosted login multi-step flow tests.
//
// The cookies path is ignored since all requests are within the same issuer
// (the max-age < 0 cookies are removed).
type oauth2Browser struct {
	t       testing.TB
	app     *tests.TestApp
	handler http.Handler
	cookies map[string]string

	// lastHTML is the body of the last HTML response
	lastHTML string

	// host is the optional default request Host (e.g. to simulate a request host different from the AppURL)
	host string
}

func newOAuth2Browser(t testing.TB, app *tests.TestApp) *oauth2Browser {
	t.Helper()

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}

	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	return &oauth2Browser{t: t, app: app, handler: mux, cookies: map[string]string{}}
}

// clone returns a new browser sharing the same router but with a copy of the cookies.
func (b *oauth2Browser) clone(withCookies bool) *oauth2Browser {
	c := &oauth2Browser{t: b.t, app: b.app, handler: b.handler, cookies: map[string]string{}, host: b.host}
	if withCookies {
		for k, v := range b.cookies {
			c.cookies[k] = v
		}
	}
	return c
}

func (b *oauth2Browser) do(method string, rawURL string, body string, headers map[string]string) (*http.Response, string) {
	b.t.Helper()

	// strip the scheme and host of absolute urls
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		rawURL = u.RequestURI()
	}

	// resolve the token placeholders (see tests.AuthToken)
	cache := map[string]string{}
	rawURL = oauth2ResolvePlaceholders(b.t, b.app, rawURL, cache)
	body = oauth2ResolvePlaceholders(b.t, b.app, body, cache)

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, rawURL, reader)
	for k, v := range headers {
		req.Header.Set(k, oauth2ResolvePlaceholders(b.t, b.app, v, cache))
	}
	if host := headers["Host"]; host != "" {
		req.Host = host
	} else if b.host != "" {
		req.Host = b.host
	}

	if len(b.cookies) > 0 && req.Header.Get("Cookie") == "" {
		parts := make([]string, 0, len(b.cookies))
		for k, v := range b.cookies {
			parts = append(parts, k+"="+v)
		}
		slices.Sort(parts)
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}

	rec := httptest.NewRecorder()
	b.handler.ServeHTTP(rec, req)
	res := rec.Result()

	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}

	raw, _ := io.ReadAll(res.Body)

	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		b.lastHTML = string(raw)
	}

	return res, string(raw)
}

func (b *oauth2Browser) get(rawURL string) (*http.Response, string) {
	b.t.Helper()
	return b.do(http.MethodGet, rawURL, "", nil)
}

// post submits a same-origin form request.
func (b *oauth2Browser) post(rawURL string, values url.Values) (*http.Response, string) {
	b.t.Helper()

	origin := oauth2TestOrigin
	if b.host != "" {
		origin = "http://" + b.host
	}

	return b.do(http.MethodPost, rawURL, values.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin":       origin,
	})
}

// submit posts the form with the provided action path of the last HTML page
// (the auth_state, csrf and token hidden fields are auto filled).
func (b *oauth2Browser) submit(action string, values map[string]string) (*http.Response, string) {
	b.t.Helper()

	form := url.Values{}
	for _, name := range []string{"auth_state", "csrf", "token"} {
		if v := hiddenField(b.lastHTML, name); v != "" {
			form.Set(name, v)
		}
	}
	for k, v := range values {
		form.Set(k, v)
	}

	return b.post(action, form)
}

// follow follows a redirect response (only to local URLs).
func (b *oauth2Browser) follow(res *http.Response) (*http.Response, string) {
	b.t.Helper()

	location := res.Header.Get("Location")
	if location == "" {
		b.t.Fatalf("Expected redirect response, got %d", res.StatusCode)
	}

	if strings.HasPrefix(location, oauth2TestRedirectURI) {
		b.t.Fatalf("Unexpected follow of the client redirect %q", location)
	}

	return b.get(location)
}

func (b *oauth2Browser) expectStatus(res *http.Response, body string, status int) {
	b.t.Helper()

	if res.StatusCode != status {
		b.t.Fatalf("Expected status %d, got %d (%s %s)", status, res.StatusCode, res.Header.Get("Location"), body)
	}
}

// authorize performs an authorization request and returns its response.
func (b *oauth2Browser) authorize(collection string, clientId string, params map[string]string) *http.Response {
	b.t.Helper()

	res, _ := b.get(oauth2AuthorizeURL(collection, clientId, params))

	return res
}

// startLogin performs an authorization request (without SSO) and opens the login page.
//
// Returns the auth_state handle.
func (b *oauth2Browser) startLogin(collection string, clientId string, params map[string]string) string {
	b.t.Helper()

	res := b.authorize(collection, clientId, params)
	b.expectStatus(res, "", http.StatusFound)

	query := oauth2ExpectRedirect(b.t, res, "/oauth2/"+collection+"/login?", map[string]string{"auth_state": "*"})

	res, body := b.follow(res)
	b.expectStatus(res, body, http.StatusOK)

	return query.Get("auth_state")
}

// loginPassword submits the password form of the current login page.
func (b *oauth2Browser) loginPassword(collection string, identity string, password string) *http.Response {
	b.t.Helper()

	res, _ := b.submit("/oauth2/"+collection+"/login/password", map[string]string{
		"identity": identity,
		"password": password,
	})

	return res
}

// expectCode checks whether the response is a code redirect to the client and returns the code.
func (b *oauth2Browser) expectCode(res *http.Response, issuer string) string {
	b.t.Helper()

	query := oauth2ExpectRedirect(b.t, res, oauth2TestRedirectURI+"?", map[string]string{
		"code":  "*",
		"state": "test_state",
		"iss":   issuer,
		"error": "",
	})

	return query.Get("code")
}

// expectError checks whether the response is an error redirect to the client.
func (b *oauth2Browser) expectError(res *http.Response, code string) {
	b.t.Helper()

	oauth2ExpectRedirect(b.t, res, oauth2TestRedirectURI+"?", map[string]string{
		"error": code,
		"state": "test_state",
		"code":  "",
	})
}

// exchange exchanges the provided code for tokens.
func (b *oauth2Browser) exchange(collection string, clientId string, code string, extra map[string]string) (*http.Response, map[string]any) {
	b.t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientId)
	form.Set("code", code)
	form.Set("redirect_uri", oauth2TestRedirectURI)
	form.Set("code_verifier", oauth2TestCodeVerifier)
	for k, v := range extra {
		if v == "" {
			form.Del(k)
		} else {
			form.Set(k, v)
		}
	}

	res, body := b.do(http.MethodPost, "/oauth2/"+collection+"/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})

	return res, parseJSONMap(b.t, body)
}

// tokenRequest sends a raw token endpoint request.
func (b *oauth2Browser) tokenRequest(collection string, values map[string]string) (*http.Response, map[string]any) {
	b.t.Helper()

	cache := map[string]string{}
	form := url.Values{}
	for k, v := range values {
		form.Set(k, oauth2ResolvePlaceholders(b.t, b.app, v, cache))
	}

	res, body := b.do(http.MethodPost, "/oauth2/"+collection+"/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})

	return res, parseJSONMap(b.t, body)
}

// sessionByHandle returns the flow session of the provided plain handle.
func (b *oauth2Browser) sessionByHandle(handle string) *core.AuthSession {
	b.t.Helper()

	session, err := b.app.FindAuthSessionByHandle(handle)
	if err != nil {
		b.t.Fatalf("Failed to find the flow session: %v", err)
	}

	return session
}

// sessionByCode returns the flow session of the provided plain authorization code.
func (b *oauth2Browser) sessionByCode(code string) *core.AuthSession {
	b.t.Helper()

	session, err := b.app.FindAuthSessionByCode(code)
	if err != nil {
		b.t.Fatalf("Failed to find the code session: %v", err)
	}

	return session
}

func parseJSONMap(t testing.TB, body string) map[string]any {
	t.Helper()

	result := map[string]any{}
	if body == "" {
		return result
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("Failed to parse JSON %q: %v", body, err)
	}

	return result
}

var hiddenFieldRegex = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// hiddenField extracts the value of the first hidden input with the provided name.
func hiddenField(rawHTML string, name string) string {
	for _, match := range hiddenFieldRegex.FindAllStringSubmatch(rawHTML, -1) {
		if match[1] == name {
			return html.UnescapeString(match[2])
		}
	}

	return ""
}

// hrefLink extracts the first href containing the provided substring.
func hrefLink(rawHTML string, contains string) string {
	for _, match := range regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(rawHTML, -1) {
		v := html.UnescapeString(match[1])
		if strings.Contains(v, contains) {
			return v
		}
	}

	return ""
}

// oauth2SetOTPPassword replaces the password of the latest OTP of the specified session
// (the real OTP is sent in the background and it is not accessible in the tests).
func oauth2SetOTPPassword(t testing.TB, app core.App, sessionId string, password string) *core.OTP {
	t.Helper()

	otp := &core.OTP{}
	err := app.RecordQuery(core.CollectionNameOTPs).
		AndWhere(dbx.HashExp{"sessionRef": sessionId}).
		OrderBy("created DESC").
		Limit(1).
		One(otp)
	if err != nil {
		t.Fatalf("Failed to find the session OTP: %v", err)
	}

	otp.SetPassword(password)
	if err := app.Save(otp); err != nil {
		t.Fatal(err)
	}

	return otp
}

var nonceRegex = regexp.MustCompile(`nonce(=|-)"?[A-Za-z0-9]+`)

func oauth2AttackApp(t *testing.T) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)

	oauth2AuthorizeSetup(t, app)

	return app
}

func oauth2CountFactors(t *testing.T, app core.App, handle string) int {
	t.Helper()

	session, err := app.FindAuthSessionByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}

	return len(session.AuthMethods())
}
