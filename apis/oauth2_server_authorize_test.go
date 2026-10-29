package apis_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/security"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// oauth2AuthorizeSetup registers the default test clients:
// first-party public "app", third-party public "3p", confidential first-party "conf",
// disabled "disabled" and "other" registered for the clients collection.
func oauth2AuthorizeSetup(t testing.TB, app *tests.TestApp) {
	oauth2PrepareIssuer(t, app, "users")
	oauth2PrepareIssuer(t, app, "clients")
	oauth2StubClient(t, app, "users", "app", oauth2FirstParty)
	oauth2StubClient(t, app, "users", "3p")
	oauth2StubClient(t, app, "users", "conf", oauth2Confidential, oauth2FirstParty)
	oauth2StubClient(t, app, "users", "disabled", func(c *core.OAuth2Client) { c.SetDisabled(true) })
	oauth2StubClient(t, app, "clients", "other", oauth2FirstParty)
}

func TestOAuth2ServerAuthorizeValidation(t *testing.T) {
	t.Parallel()

	expectErrorRedirect := func(code string) func(t testing.TB, app *tests.TestApp, res *http.Response) {
		return func(t testing.TB, app *tests.TestApp, res *http.Response) {
			oauth2ExpectRedirect(t, res, oauth2TestRedirectURI+"?", map[string]string{
				"error":             code,
				"error_description": "*",
				"state":             "test_state",
				"iss":               oauth2TestIssuer,
				"code":              "",
			})

			// no flow session is created for invalid requests
			total, _ := app.CountRecords(core.CollectionNameAuthSessions)
			if total != 0 {
				t.Fatalf("Expected no auth sessions, got %d", total)
			}
		}
	}

	expectNoSessions := func(t testing.TB, app *tests.TestApp, res *http.Response) {
		total, _ := app.CountRecords(core.CollectionNameAuthSessions)
		if total != 0 {
			t.Fatalf("Expected no auth sessions, got %d", total)
		}
	}

	pageError := func(name string, url string, status int) tests.ApiScenario {
		return tests.ApiScenario{
			Name:   name,
			Method: http.MethodGet,
			URL:    url,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2AuthorizeSetup(t, app)
			},
			ExpectedStatus:  status,
			ExpectedContent: []string{"Something went wrong"},
			NotExpectedContent: []string{
				// no client redirects for unverified clients/redirect uris
				"https://example.com",
			},
			AfterTestFunc:  expectNoSessions,
			ExpectedEvents: map[string]int{"*": 0},
		}
	}

	redirectError := func(name string, url string, code string, extraSetup ...func(t testing.TB, app *tests.TestApp)) tests.ApiScenario {
		return tests.ApiScenario{
			Name:   name,
			Method: http.MethodGet,
			URL:    url,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2AuthorizeSetup(t, app)
				for _, s := range extraSetup {
					s(t, app)
				}
			},
			ExpectedStatus: http.StatusFound,
			AfterTestFunc:  expectErrorRedirect(code),
			ExpectedEvents: map[string]int{"*": 0},
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "non-auth collection",
			Method:          http.MethodGet,
			URL:             oauth2AuthorizeURL("demo1", "app", nil),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		pageError("missing client_id", oauth2AuthorizeURL("users", "", nil), 400),
		pageError("unknown client", oauth2AuthorizeURL("users", "missing", nil), 400),
		pageError("disabled client", oauth2AuthorizeURL("users", "disabled", nil), 400),
		pageError("client from another collection", oauth2AuthorizeURL("users", "other", nil), 400),
		pageError("missing redirect_uri", oauth2AuthorizeURL("users", "app", map[string]string{"redirect_uri": ""}), 400),
		pageError("unregistered redirect_uri (no open redirect)", oauth2AuthorizeURL("users", "app", map[string]string{"redirect_uri": "https://evil.example.com/callback"}), 400),
		pageError("duplicated client_id", oauth2AuthorizeURL("users", "app", nil)+"&client_id=app", 400),
		redirectError("duplicated state", oauth2AuthorizeURL("users", "app", nil)+"&state=abc", "invalid_request"),
		redirectError("unsupported response_type", oauth2AuthorizeURL("users", "app", map[string]string{"response_type": "token"}), "unsupported_response_type"),
		redirectError("unsupported response_mode", oauth2AuthorizeURL("users", "app", map[string]string{"response_mode": "fragment"}), "invalid_request"),
		redirectError("request object", oauth2AuthorizeURL("users", "app", map[string]string{"request": "abc"}), "request_not_supported"),
		redirectError("request_uri", oauth2AuthorizeURL("users", "app", map[string]string{"request_uri": "abc"}), "request_uri_not_supported"),
		redirectError("missing scope", oauth2AuthorizeURL("users", "app", map[string]string{"scope": ""}), "invalid_scope"),
		redirectError("scope not supported by the collection", oauth2AuthorizeURL("users", "app", map[string]string{"scope": "openid unknown"}), "invalid_scope"),
		redirectError(
			"scope not allowed for the client (deny by default)",
			oauth2AuthorizeURL("users", "3p", map[string]string{"scope": "openid posts:read"}),
			"invalid_scope",
			func(t testing.TB, app *tests.TestApp) {
				client := oauth2FindClient(t, app, "3p")
				client.SetScopes([]string{"openid"})
				if err := app.Save(client); err != nil {
					t.Fatal(err)
				}
			},
		),
		redirectError("public client without PKCE", oauth2AuthorizeURL("users", "app", map[string]string{"code_challenge": "", "code_challenge_method": ""}), "invalid_request"),
		redirectError("confidential client without PKCE", oauth2AuthorizeURL("users", "conf", map[string]string{"code_challenge": "", "code_challenge_method": ""}), "invalid_request"),
		redirectError("plain code_challenge_method", oauth2AuthorizeURL("users", "app", map[string]string{"code_challenge_method": "plain"}), "invalid_request"),
		redirectError("missing code_challenge_method", oauth2AuthorizeURL("users", "app", map[string]string{"code_challenge_method": ""}), "invalid_request"),
		redirectError("invalid code_challenge format", oauth2AuthorizeURL("users", "app", map[string]string{"code_challenge": "short"}), "invalid_request"),
		redirectError("unsupported prompt", oauth2AuthorizeURL("users", "app", map[string]string{"prompt": "unknown"}), "invalid_request"),
		redirectError("prompt none combined with other values", oauth2AuthorizeURL("users", "app", map[string]string{"prompt": "none login"}), "invalid_request"),
		redirectError("invalid max_age", oauth2AuthorizeURL("users", "app", map[string]string{"max_age": "-1"}), "invalid_request"),
		redirectError("too long nonce", oauth2AuthorizeURL("users", "app", map[string]string{"nonce": strings.Repeat("a", 513)}), "invalid_request"),
		redirectError("prompt=none without SSO session", oauth2AuthorizeURL("users", "app", map[string]string{"prompt": "none"}), "login_required"),
		redirectError(
			"third-party client for the _superusers issuer",
			oauth2AuthorizeURL("_superusers", "su3p", nil),
			"unauthorized_client",
			func(t testing.TB, app *tests.TestApp) {
				oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
				su, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
				client := core.NewOAuth2Client(app)
				client.SetName("su3p")
				client.SetClientId("su3p")
				client.SetType(core.OAuth2ClientTypePublic)
				client.SetCollectionRef(su.Id)
				client.SetRedirectURIs([]string{oauth2TestRedirectURI})
				client.SetScopes([]string{"openid"})
				// saved without validation (the first-party only rule is enforced on validate)
				if err := app.SaveNoValidate(client); err != nil {
					t.Fatal(err)
				}
			},
		),
	}

	for _, s := range scenarios {
		if s.Name == "third-party client for the _superusers issuer" {
			// the issuer of the error redirect is the _superusers one
			s.AfterTestFunc = func(t testing.TB, app *tests.TestApp, res *http.Response) {
				oauth2ExpectRedirect(t, res, oauth2TestRedirectURI+"?", map[string]string{
					"error": "unauthorized_client",
					"iss":   "http://localhost:8090/oauth2/_superusers",
				})
			}
		}
		s.Test(t)
	}
}

func TestOAuth2ServerAuthorizeCreatesFlowSession(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)

	res := b.authorize("users", "3p", map[string]string{
		"scope":      "openid email posts:read",
		"login_hint": "test@example.com",
		"max_age":    "300",
		"ui_locales": "en",
		"prompt":     "consent",
	})
	b.expectStatus(res, "", http.StatusFound)

	query := oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"auth_state": "*"})
	handle := query.Get("auth_state")

	session := b.sessionByHandle(handle)

	if session.Status() != core.AuthSessionStatusPending {
		t.Fatalf("Expected pending session, got %q", session.Status())
	}
	if session.RecordRef() != "" {
		t.Fatalf("Expected no actor, got %q", session.RecordRef())
	}
	if session.Client() != oauth2FindClient(t, app, "3p").Id {
		t.Fatal("Unexpected session client")
	}
	if session.RedirectURI() != oauth2TestRedirectURI ||
		session.State() != "test_state" ||
		session.Nonce() != "test_nonce" ||
		session.CodeChallenge() != oauth2TestCodeChallenge ||
		session.CodeChallengeMethod() != "S256" ||
		session.LoginHint() != "test@example.com" ||
		session.UILocales() != "en" ||
		session.MaxAge() != 300 ||
		session.Prompt() != "consent" {
		t.Fatalf("Unexpected session authorization request data %v", session.PublicExport())
	}
	if !slices.Equal(session.ScopesRequested(), []string{"openid", "email", "posts:read"}) {
		t.Fatalf("Unexpected requested scopes %v", session.ScopesRequested())
	}
	if len(session.Scopes()) != 0 {
		t.Fatalf("Expected no granted scopes yet, got %v", session.Scopes())
	}

	// the handle is never stored plain
	if strings.Contains(session.GetString("handleHash"), handle) || session.GetString("handleHash") == "" {
		t.Fatal("Expected the handle to be stored hashed")
	}

	// binding cookie
	binding := b.cookies["pb_binding_"+session.Id]
	if binding == "" || !session.ValidateBinding(binding) {
		t.Fatalf("Expected valid binding cookie, got %v", b.cookies)
	}
	var bindingCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "pb_binding_"+session.Id {
			bindingCookie = c
		}
	}
	if bindingCookie == nil || !bindingCookie.HttpOnly || bindingCookie.SameSite != http.SameSiteLaxMode || bindingCookie.Path != "/oauth2/users" {
		t.Fatalf("Unexpected binding cookie %#v", bindingCookie)
	}

	expiresIn := time.Until(session.ExpiresAt().Time())
	if expiresIn <= 0 || expiresIn > core.AuthSessionFlowDuration {
		t.Fatalf("Unexpected flow session expiration %v", session.ExpiresAt())
	}

	// the login page renders the collection enabled methods (no JS, no vanilla auth endpoints)
	res, body := b.follow(res)
	b.expectStatus(res, body, http.StatusOK)

	for _, expected := range []string{
		`action="/oauth2/users/login/password"`,
		`action="/oauth2/users/login/otp"`,
		`/oauth2/users/login/oauth2/gitlab?auth_state=`,
		`/oauth2/users/login/oauth2/google?auth_state=`,
		`/oauth2/users/signup?auth_state=`,
		`/oauth2/users/password-reset?auth_state=`,
		`value="test@example.com"`,
		`name="csrf"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("Expected %q in the login page:\n%s", expected, body)
		}
	}

	for _, notExpected := range []string{"<script", "/api/collections/", "/api/realtime"} {
		if strings.Contains(body, notExpected) {
			t.Fatalf("Unexpected %q in the login page:\n%s", notExpected, body)
		}
	}

	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "style-src 'nonce-") {
		t.Fatalf("Unexpected CSP %q", csp)
	}

	// the form serialized POST authorization request is also supported
	form := strings.SplitN(oauth2AuthorizeURL("users", "app", nil), "?", 2)[1]
	res, _ = b.do(http.MethodPost, "/oauth2/users/authorize", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	b.expectStatus(res, "", http.StatusSeeOther)
	oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"auth_state": "*"})
}

func TestOAuth2ServerLoginMethodsFromCollectionOptions(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	users, _ := app.FindCollectionByNameOrId("users")
	users.OTP.Enabled = false
	users.OAuth2.Enabled = false
	users.CreateRule = nil
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)

	if !strings.Contains(b.lastHTML, "/login/password") {
		t.Fatal("Expected the password form")
	}

	for _, notExpected := range []string{"/login/otp", "/login/oauth2/", "/signup"} {
		if strings.Contains(b.lastHTML, notExpected) {
			t.Fatalf("Unexpected %q for the disabled collection method", notExpected)
		}
	}

	// the disabled methods are rejected even if submitted directly
	res, body := b.submit("/oauth2/users/login/otp", map[string]string{"email": "test@example.com"})
	b.expectStatus(res, body, http.StatusBadRequest)
	total, _ := app.CountRecords(core.CollectionNameOTPs)
	if total != 0 {
		t.Fatalf("Expected no OTPs, got %d", total)
	}

	res, body = b.get("/oauth2/users/signup?auth_state=" + hiddenField(b.lastHTML, "auth_state"))
	b.expectStatus(res, body, http.StatusNotFound)
}

func TestOAuth2ServerPasswordLoginFirstParty(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")

	b := newOAuth2Browser(t, app)
	handle := b.startLogin("users", "app", map[string]string{"scope": "openid email offline_access"})

	res := b.loginPassword("users", "test@example.com", "1234567890")
	b.expectStatus(res, "", http.StatusSeeOther)

	code := b.expectCode(res, oauth2TestIssuer)

	session := b.sessionByCode(code)
	if session.Status() != core.AuthSessionStatusAuthorized {
		t.Fatalf("Expected authorized session, got %q", session.Status())
	}
	if session.RecordRef() != user.Id {
		t.Fatalf("Expected actor %q, got %q", user.Id, session.RecordRef())
	}
	if !session.HasAuthMethod(core.AuthSessionMethodPassword) || session.AuthTime().IsZero() {
		t.Fatalf("Expected password amr and auth time, got %v", session.AuthMethods())
	}
	if !slices.Equal(session.Scopes(), []string{"openid", "email", "offline_access"}) {
		t.Fatalf("Unexpected granted scopes %v", session.Scopes())
	}
	if session.Id != b.sessionByHandle(handle).Id {
		t.Fatal("Expected the same flow session")
	}

	// the binding cookie is removed after the code is issued
	if _, ok := b.cookies["pb_binding_"+session.Id]; ok {
		t.Fatal("Expected the binding cookie to be removed")
	}

	// root SSO session
	ssoCookie := b.cookies["pb_session"]
	if ssoCookie == "" {
		t.Fatal("Expected pb_session cookie")
	}
	rootId, secret, _ := strings.Cut(ssoCookie, ".")
	root := oauth2ReloadSession(t, app, rootId)
	if !root.IsRoot() || !root.IsActive() || !root.ValidateSSOSecret(secret) || root.RecordRef() != user.Id {
		t.Fatalf("Unexpected root SSO session %v", root.PublicExport())
	}
	if session.Parent() != root.Id {
		t.Fatalf("Expected the flow session parent %q, got %q", root.Id, session.Parent())
	}
	users, _ := app.FindCollectionByNameOrId("users")
	if d := time.Until(root.ExpiresAt().Time()) - users.OAuth2Server.SessionDurationTime(); d > 5*time.Second || d < -5*time.Second {
		t.Fatalf("Expected root expiration ~SessionDuration, got %v", root.ExpiresAt())
	}

	// code exchange
	res, data := b.exchange("users", "app", code, nil)
	b.expectStatus(res, "", http.StatusOK)

	accessToken, _ := data["access_token"].(string)
	if accessToken == "" || data["refresh_token"] == "" || data["id_token"] == "" || data["token_type"] != "Bearer" {
		t.Fatalf("Unexpected token response %v", data)
	}
	if data["expires_in"] != float64(users.AuthToken.Duration) {
		t.Fatalf("Expected expires_in %d (AuthToken.Duration), got %v", users.AuthToken.Duration, data["expires_in"])
	}

	session = oauth2ReloadSession(t, app, session.Id)
	if session.Status() != core.AuthSessionStatusActive || !session.HasRefreshToken() {
		t.Fatalf("Expected active session with refresh token, got %q", session.Status())
	}

	// the access token is a valid session-backed record auth token
	record, err := app.FindAuthRecordByToken(accessToken, core.TokenTypeAuth)
	if err != nil || record.Id != user.Id {
		t.Fatalf("Expected valid access token, got %v", err)
	}

	res, body := b.do(http.MethodGet, "/api/collections/users/records/"+user.Id, "", map[string]string{"Authorization": accessToken})
	b.expectStatus(res, body, http.StatusOK)
}

func TestOAuth2ServerLoginGenericErrors(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)
	handle := b.startLogin("users", "app", nil)

	scenarios := []struct {
		identity string
		password string
	}{
		{"test@example.com", "wrong_password"},
		{"missing@example.com", "1234567890"},
		{"missing_username", "1234567890"},
		{"", ""},
	}

	var firstBody string
	for i, s := range scenarios {
		res := b.loginPassword("users", s.identity, s.password)
		b.expectStatus(res, b.lastHTML, http.StatusBadRequest)

		if !strings.Contains(b.lastHTML, "Invalid login credentials.") {
			t.Fatalf("[%d] Expected generic error, got %s", i, b.lastHTML)
		}

		// strip the variable parts (nonce, csrf) to compare the responses
		body := regexpReplaceVariable(b.lastHTML)
		if firstBody == "" {
			firstBody = body
		} else if body != firstBody {
			t.Fatalf("[%d] Expected identical responses for existing and missing accounts", i)
		}
	}

	// the flow remains pending and could still continue
	session := b.sessionByHandle(handle)
	if session.Status() != core.AuthSessionStatusPending || session.RecordRef() != "" {
		t.Fatalf("Expected pending flow without actor, got %q %q", session.Status(), session.RecordRef())
	}

	res := b.loginPassword("users", "test@example.com", "1234567890")
	b.expectCode(res, oauth2TestIssuer)
}

func regexpReplaceVariable(html string) string {
	for _, name := range []string{"nonce", "csrf"} {
		html = strings.ReplaceAll(html, hiddenField(html, name), "")
	}

	if i := strings.Index(html, "nonce=\""); i >= 0 {
		end := strings.Index(html[i+7:], "\"")
		html = html[:i] + html[i+7+end:]
	}

	return html
}

func TestOAuth2ServerFlowHandleBindingAndCSRF(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)
	handle := b.startLogin("users", "app", nil)
	loginHTML := b.lastHTML
	csrf := hiddenField(loginHTML, "csrf")
	session := b.sessionByHandle(handle)

	other := newOAuth2Browser(t, app)
	otherHandle := other.startLogin("users", "app", nil)

	passwordForm := func(handle string, csrf string) map[string]string {
		return map[string]string{
			"auth_state": handle,
			"csrf":       csrf,
			"identity":   "test@example.com",
			"password":   "1234567890",
		}
	}

	expectInvalid := func(name string, res *http.Response, body string) {
		t.Helper()
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Something went wrong") {
			t.Fatalf("[%s] Expected invalid flow/form page, got %d %s", name, res.StatusCode, body)
		}
		if strings.Contains(res.Header.Get("Location"), "code=") {
			t.Fatalf("[%s] Unexpected code redirect", name)
		}
	}

	// GET steps without/with invalid handle
	res, body := b.get("/oauth2/users/login")
	expectInvalid("missing handle", res, body)

	res, body = b.get("/oauth2/users/login?auth_state=invalid")
	expectInvalid("invalid handle", res, body)

	// the same handle from another issuer
	res, body = b.get("/oauth2/clients/login?auth_state=" + handle)
	expectInvalid("handle of another issuer", res, body)

	// the handle without the binding cookie (e.g. a leaked login URL)
	stranger := newOAuth2Browser(t, app)
	res, body = stranger.get("/oauth2/users/login?auth_state=" + handle)
	expectInvalid("missing binding cookie", res, body)

	// the handle with the binding cookie of another flow
	res, body = other.get("/oauth2/users/login?auth_state=" + handle)
	expectInvalid("binding cookie of another flow", res, body)

	// forged binding cookie value
	forged := b.clone(true)
	forged.cookies["pb_binding_"+session.Id] = "forged"
	res, body = forged.get("/oauth2/users/login?auth_state=" + handle)
	expectInvalid("forged binding cookie", res, body)

	// POST without the binding cookie
	strangerWithCSRF := b.clone(true)
	delete(strangerWithCSRF.cookies, "pb_binding_"+session.Id)
	res, body = strangerWithCSRF.post("/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, csrf)))
	expectInvalid("POST without binding cookie", res, body)

	// missing csrf
	res, body = b.post("/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, "")))
	expectInvalid("missing csrf", res, body)

	// invalid csrf
	res, body = b.post("/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, oauth2TestCSRF)))
	expectInvalid("invalid csrf", res, body)

	// cross-site form submission
	res, body = b.do(http.MethodPost, "/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, csrf)).Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin":       "https://evil.example.com",
	})
	expectInvalid("cross-site origin", res, body)

	res, body = b.do(http.MethodPost, "/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, csrf)).Encode(), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Sec-Fetch-Site": "cross-site",
	})
	expectInvalid("cross-site fetch metadata", res, body)

	// handle of another flow with this browser binding cookie
	res, body = b.post("/oauth2/users/login/password", oauth2URLValues(passwordForm(otherHandle, csrf)))
	expectInvalid("handle of another flow", res, body)

	// none of the invalid submissions identified the actor
	if s := oauth2ReloadSession(t, app, session.Id); s.RecordRef() != "" || len(s.AuthMethods()) != 0 {
		t.Fatalf("Expected no factors, got %v", s.AuthMethods())
	}

	// expired flow
	expired := b.sessionByHandle(otherHandle)
	expired.SetExpiresAt(types.NowDateTime().Add(-time.Second))
	if err := app.Save(expired); err != nil {
		t.Fatal(err)
	}
	res, body = other.get("/oauth2/users/login?auth_state=" + otherHandle)
	expectInvalid("expired flow", res, body)

	// valid submission
	res, _ = b.post("/oauth2/users/login/password", oauth2URLValues(passwordForm(handle, csrf)))
	b.expectCode(res, oauth2TestIssuer)

	// the authorized (aka. completed) flow handle can't be reused
	res, body = b.get("/oauth2/users/login?auth_state=" + handle)
	expectInvalid("completed flow", res, body)
}

func oauth2URLValues(values map[string]string) url.Values {
	result := url.Values{}
	for k, v := range values {
		result[k] = []string{v}
	}
	return result
}

func TestOAuth2ServerConsentFlow(t *testing.T) {
	t.Parallel()

	t.Run("allow, remember and reuse", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		client := oauth2FindClient(t, app, "3p")

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "3p", map[string]string{"scope": "openid email posts:read"})

		res := b.loginPassword("users", "test@example.com", "1234567890")
		b.expectStatus(res, "", http.StatusSeeOther)
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/consent?", map[string]string{"auth_state": "*"})

		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)
		for _, expected := range []string{"Test App 3p", "Verify your identity", "View your email address", "posts:read", user.Email()} {
			if !strings.Contains(body, expected) {
				t.Fatalf("Expected %q in the consent page", expected)
			}
		}

		res, _ = b.submit("/oauth2/users/consent", map[string]string{"decision": "allow"})
		code := b.expectCode(res, oauth2TestIssuer)
		if s := b.sessionByCode(code); s.Status() != core.AuthSessionStatusAuthorized {
			t.Fatalf("Expected authorized session, got %q", s.Status())
		}

		consent, err := app.FindOAuth2ConsentByRecordAndClient(user, client)
		if err != nil || !consent.Covers([]string{"openid", "email", "posts:read"}) {
			t.Fatalf("Expected remembered consent, got %v", err)
		}

		// SSO + remembered consent -> direct code
		res = b.authorize("users", "3p", map[string]string{"scope": "openid email"})
		b.expectCode(res, oauth2TestIssuer)

		// remembered consent not covering the new scope -> consent page
		res = b.authorize("users", "3p", map[string]string{"scope": "openid profile"})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/consent?", nil)

		// prompt=consent forces the consent page even for first-party clients
		res = b.authorize("users", "app", map[string]string{"prompt": "consent"})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/consent?", nil)

		// prompt=none with required consent
		res = b.authorize("users", "3p", map[string]string{"scope": "openid profile", "prompt": "none"})
		b.expectError(res, "consent_required")
	})

	t.Run("deny", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "3p", nil)
		session := b.sessionByHandle(handle)

		res := b.loginPassword("users", "test@example.com", "1234567890")
		b.follow(res)

		res, _ = b.submit("/oauth2/users/consent", map[string]string{"decision": "deny"})
		b.expectError(res, "access_denied")

		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusFailed {
			t.Fatalf("Expected failed session, got %q", s.Status())
		}

		total, _ := app.CountRecords(core.CollectionNameOAuth2Consents)
		if total != 0 {
			t.Fatalf("Expected no remembered consents, got %d", total)
		}
	})

	t.Run("consent not required by the collection", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.OAuth2Server.ConsentRequired = false
		})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "3p", nil)
		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
	})

	t.Run("consent page of a pending flow redirects to login", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "3p", nil)

		res, _ := b.get("/oauth2/users/consent?auth_state=" + handle)
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"auth_state": handle})

		// the consent POST can't bypass the login
		res, _ = b.submit("/oauth2/users/consent", map[string]string{"decision": "allow", "auth_state": handle})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", nil)
	})
}

func TestOAuth2ServerSSO(t *testing.T) {
	t.Parallel()

	var nonRootSessionId string

	type scenario struct {
		name     string
		authTime time.Duration // relative to now
		params   map[string]string
		modify   func(t testing.TB, app *tests.TestApp, root *core.AuthSession)
		cookie   func(cookie string) string
		expect   string // "code", "login", or error code
	}

	scenarios := []scenario{
		{name: "reuse", expect: "code"},
		{name: "reuse with prompt=none", params: map[string]string{"prompt": "none"}, expect: "code"},
		{name: "prompt=login", params: map[string]string{"prompt": "login"}, expect: "login"},
		{name: "prompt=select_account", params: map[string]string{"prompt": "select_account"}, expect: "login"},
		{name: "max_age satisfied", authTime: -1 * time.Minute, params: map[string]string{"max_age": "300"}, expect: "code"},
		{name: "max_age exceeded", authTime: -10 * time.Minute, params: map[string]string{"max_age": "300"}, expect: "login"},
		{name: "max_age=0", authTime: -2 * time.Second, params: map[string]string{"max_age": "0"}, expect: "login"},
		{name: "max_age exceeded with prompt=none", authTime: -10 * time.Minute, params: map[string]string{"max_age": "300", "prompt": "none"}, expect: "login_required"},
		{
			name:   "invalid sso secret",
			cookie: func(cookie string) string { return cookie + "x" },
			expect: "login",
		},
		{
			name:   "malformed sso cookie",
			cookie: func(cookie string) string { return "pb_session=abc" },
			expect: "login",
		},
		{
			name: "ended root",
			modify: func(t testing.TB, app *tests.TestApp, root *core.AuthSession) {
				_ = root.End()
				if err := app.Save(root); err != nil {
					t.Fatal(err)
				}
			},
			expect: "login",
		},
		{
			name: "expired root",
			modify: func(t testing.TB, app *tests.TestApp, root *core.AuthSession) {
				root.SetExpiresAt(types.NowDateTime().Add(-time.Second))
				if err := app.Save(root); err != nil {
					t.Fatal(err)
				}
			},
			expect: "login",
		},
		{
			name: "root ended by password change",
			modify: func(t testing.TB, app *tests.TestApp, root *core.AuthSession) {
				user := oauth2FindRecord(t, app, "users", "test@example.com")
				user.SetPassword("new_password_123")
				if err := app.Save(user); err != nil {
					t.Fatal(err)
				}
			},
			expect: "login",
		},
		{
			name: "non-root session as sso cookie",
			cookie: func(cookie string) string {
				return "pb_session=" + nonRootSessionId + ".secret"
			},
			expect: "login",
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2AuthorizeSetup(t, app)

			user := oauth2FindRecord(t, app, "users", "test@example.com")
			client := oauth2FindClient(t, app, "app")

			_, nonRoot := oauth2AccessToken(t, app, client, user, []string{"openid"})
			nonRootSessionId = nonRoot.Id

			cookie, root := oauth2StubSSO(t, app, user, types.NowDateTime().Add(s.authTime))
			if s.modify != nil {
				s.modify(t, app, root)
			}
			if s.cookie != nil {
				cookie = s.cookie(cookie)
			}

			b := newOAuth2Browser(t, app)
			res, _ := b.do(http.MethodGet, oauth2AuthorizeURL("users", "app", s.params), "", map[string]string{"Cookie": cookie})

			switch s.expect {
			case "code":
				code := b.expectCode(res, oauth2TestIssuer)
				session := b.sessionByCode(code)
				if session.Parent() != root.Id || session.RecordRef() != user.Id {
					t.Fatalf("Expected child session of root %q, got parent %q", root.Id, session.Parent())
				}
				if session.AuthTime().String() != root.AuthTime().String() {
					t.Fatalf("Expected inherited auth time %v, got %v", root.AuthTime(), session.AuthTime())
				}
				if len(session.AuthMethods()) != 1 || session.AuthMethods()[0].Method != core.AuthSessionMethodPassword {
					t.Fatalf("Expected inherited amr, got %v", session.AuthMethods())
				}
			case "login":
				oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", map[string]string{"auth_state": "*"})
			default:
				b.expectError(res, s.expect)
			}
		})
	}

	t.Run("sso of another issuer is ignored", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		clientsUser := oauth2FindRecord(t, app, "clients", "test@example.com")
		cookie, _ := oauth2StubSSO(t, app, clientsUser, types.NowDateTime())

		b := newOAuth2Browser(t, app)
		res, _ := b.do(http.MethodGet, oauth2AuthorizeURL("users", "app", nil), "", map[string]string{"Cookie": cookie})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", nil)
	})

	t.Run("prompt=login re-authentication refreshes the existing root", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
		firstRoot := b.cookies["pb_session"]

		b.startLogin("users", "app", map[string]string{"prompt": "login"})
		code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

		if b.cookies["pb_session"] != firstRoot {
			t.Fatal("Expected the same root SSO session for the same actor")
		}
		rootId, _, _ := strings.Cut(firstRoot, ".")
		if b.sessionByCode(code).Parent() != rootId {
			t.Fatal("Expected the new flow to be a child of the existing root")
		}
	})

	t.Run("login as another actor ends the previous root and its children", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
		_, data := b.exchange("users", "app", code, nil)
		firstToken, _ := data["access_token"].(string)
		firstRootId, _, _ := strings.Cut(b.cookies["pb_session"], ".")

		b.startLogin("users", "app", map[string]string{"prompt": "login"})
		b.expectCode(b.loginPassword("users", "test2@example.com", "1234567890"), oauth2TestIssuer)

		if strings.HasPrefix(b.cookies["pb_session"], firstRootId+".") {
			t.Fatal("Expected a new root SSO session")
		}
		if s := oauth2ReloadSession(t, app, firstRootId); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the previous root to be ended, got %q", s.Status())
		}
		if _, err := app.FindAuthRecordByToken(firstToken, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the previous root child token to be invalid")
		}
	})
}

func TestOAuth2ServerAuthRuleAndSuperuserIPs(t *testing.T) {
	t.Parallel()

	t.Run("AuthRule failure", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.AuthRule = types.Pointer("verified = true")
		})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		// test@example.com is not verified
		res := b.loginPassword("users", "test@example.com", "1234567890")
		b.expectError(res, "access_denied")

		if s := b.sessionByHandle(handle); s.Status() != core.AuthSessionStatusFailed {
			t.Fatalf("Expected failed session, got %q", s.Status())
		}
		if _, ok := b.cookies["pb_session"]; ok {
			t.Fatal("Expected no SSO session")
		}

		// verified user
		b2 := newOAuth2Browser(t, app)
		b2.startLogin("users", "app", nil)
		b2.expectCode(b2.loginPassword("users", "test2@example.com", "1234567890"), oauth2TestIssuer)
	})

	t.Run("nil AuthRule (authentication disabled)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.AuthRule = nil
		})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.expectError(b.loginPassword("users", "test2@example.com", "1234567890"), "access_denied")
	})

	t.Run("staff issuer with SuperuserIPs", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
		oauth2StubClient(t, app, core.CollectionNameSuperusers, "dashboard", oauth2FirstParty, func(c *core.OAuth2Client) {
			c.SetScopes([]string{"openid", "email"})
		})

		b := newOAuth2Browser(t, app)
		b.startLogin(core.CollectionNameSuperusers, "dashboard", nil)

		// no upstream providers and no signup for superusers
		if strings.Contains(b.lastHTML, "/login/oauth2/") || strings.Contains(b.lastHTML, "/signup") {
			t.Fatal("Unexpected upstream providers or signup on the staff issuer")
		}

		code := b.expectCode(b.loginPassword(core.CollectionNameSuperusers, "test@example.com", "1234567890"), "http://localhost:8090/oauth2/_superusers")
		_, data := b.exchange(core.CollectionNameSuperusers, "dashboard", code, nil)
		token, _ := data["access_token"].(string)

		res, body := b.do(http.MethodGet, "/api/collections/_superusers/records", "", map[string]string{"Authorization": token})
		b.expectStatus(res, body, http.StatusOK)

		// non-whitelisted IP
		app.Settings().SuperuserIPs = []string{"1.2.3.4"}
		if err := app.Save(app.Settings()); err != nil {
			t.Fatal(err)
		}

		b2 := newOAuth2Browser(t, app)
		b2.startLogin(core.CollectionNameSuperusers, "dashboard", nil)
		res = b2.loginPassword(core.CollectionNameSuperusers, "test@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, oauth2TestRedirectURI+"?", map[string]string{"error": "access_denied"})
	})
}

func TestOAuth2ServerSSORootIndependentOfClients(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	rootId, _, _ := strings.Cut(b.cookies["pb_session"], ".")
	root := oauth2ReloadSession(t, app, rootId)

	// the root is a standalone browser session row (no client, handle, code or token family)
	if !root.IsRoot() || root.Client() != "" || root.GetString("handleHash") != "" || root.GetString("codeHash") != "" || root.HasRefreshToken() || root.Parent() != "" {
		t.Fatalf("Expected standalone root, got %v", root.Record.FieldsData())
	}

	// the first flow session is also a child of the root
	first := b.sessionByCode(code)
	if first.Parent() != root.Id || first.IsRoot() {
		t.Fatalf("Expected the first flow session to be a child of the root, got parent %q", first.Parent())
	}

	_, data := b.exchange("users", "app", code, nil)
	appToken, _ := data["access_token"].(string)

	// disabling the client of the first login ends only its sessions
	client := oauth2FindClient(t, app, "app")
	client.SetDisabled(true)
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	if s := oauth2ReloadSession(t, app, root.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the root to remain active, got %q", s.Status())
	}
	if _, err := app.FindAuthRecordByToken(appToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the disabled client token to be invalid")
	}

	// SSO still works for the other clients
	confCode := b.expectCode(b.authorize("users", "conf", nil), oauth2TestIssuer)
	if b.sessionByCode(confCode).Parent() != root.Id {
		t.Fatal("Expected the new flow to be a child of the same root")
	}

	// deleting a client doesn't affect the root either
	if err := app.Delete(oauth2FindClient(t, app, "conf")); err != nil {
		t.Fatal(err)
	}
	if s := oauth2ReloadSession(t, app, root.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the root to remain active after the client delete, got %q", s.Status())
	}
	// (consent_required and not login_required -> the SSO actor was reused)
	b.expectError(b.authorize("users", "3p", map[string]string{"prompt": "none", "scope": "openid"}), "consent_required")
}

func TestOAuth2ServerSSOReuseMFAStepUp(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, modifiers ...func(c *core.Collection)) (*tests.TestApp, *core.Record) {
		app, _ := tests.NewTestApp()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", append([]func(c *core.Collection){func(c *core.Collection) {
			c.OTP.Enabled = true
			c.MFA.Enabled = true
			c.MFA.Duration = 1800
		}}, modifiers...)...)

		// note: unverified with pre-existing external auths
		// (the step-up OTP verified upgrade must not break the flow)
		return app, oauth2FindRecord(t, app, "users", "test@example.com")
	}

	// stubSSO creates a root with the provided amr and sets its cookie to a new browser
	stubSSO := func(t testing.TB, app *tests.TestApp, user *core.Record, methods []core.AuthSessionMethod) (*oauth2Browser, *core.AuthSession) {
		cookie, root := oauth2StubSSO(t, app, user, methods[len(methods)-1].Time)
		root.SetAuthMethods(methods)
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		b := newOAuth2Browser(t, app)
		b.cookies["pb_session"] = strings.TrimPrefix(cookie, "pb_session=")

		return b, root
	}

	t.Run("single factor root -> step-up MFA", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		b, root := stubSSO(t, app, user, []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}})

		res := b.authorize("users", "app", nil)
		query := oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", map[string]string{"auth_state": "*"})

		session := b.sessionByHandle(query.Get("auth_state"))
		if session.Status() != core.AuthSessionStatusPending || session.RecordRef() != user.Id || !session.MFARequired() || session.Parent() != root.Id {
			t.Fatalf("Unexpected step-up session %v", session.PublicExport())
		}

		// complete the second factor
		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)
		res, body = b.submit("/oauth2/users/login/otp", nil)
		b.expectStatus(res, body, http.StatusOK)
		oauth2SetOTPPassword(t, app, session.Id, "12345678")
		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		code := b.expectCode(res, oauth2TestIssuer)

		// note: the verified upgrade ends the old root -> the flow is re-rooted
		completed := b.sessionByCode(code)
		if completed.Parent() == root.Id {
			t.Fatal("Expected the flow to be re-rooted")
		}

		// the root factors include the step-up -> the next reuse issues a code directly
		if r := oauth2ReloadSession(t, app, completed.Parent()); !r.IsActive() || len(r.DistinctAuthMethods(time.Now().Add(-time.Hour))) < 2 {
			t.Fatalf("Expected an active root with 2 distinct factors, got %v", r.AuthMethods())
		}
		b.expectCode(b.authorize("users", "app", nil), oauth2TestIssuer)
	})

	t.Run("single factor root with prompt=none -> interaction_required", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}})

		b.expectError(b.authorize("users", "app", map[string]string{"prompt": "none"}), "interaction_required")
	})

	t.Run("two factors root within MFA.Duration -> code", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		now := types.NowDateTime()
		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{
			{Method: core.AuthSessionMethodPassword, Time: now.Add(-time.Minute)},
			{Method: core.AuthSessionMethodOTP, Time: now},
		})

		b.expectCode(b.authorize("users", "app", nil), oauth2TestIssuer)
		b.expectCode(b.authorize("users", "app", map[string]string{"prompt": "none"}), oauth2TestIssuer)
	})

	t.Run("two factors root but one outside MFA.Duration -> step-up", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		now := types.NowDateTime()
		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{
			{Method: core.AuthSessionMethodPassword, Time: now.Add(-time.Hour)},
			{Method: core.AuthSessionMethodOTP, Time: now},
		})

		oauth2ExpectRedirect(t, b.authorize("users", "app", nil), oauth2TestPages+"/login/mfa?", map[string]string{"auth_state": "*"})
		b.expectError(b.authorize("users", "app", map[string]string{"prompt": "none"}), "interaction_required")
	})

	t.Run("same method twice is not MFA", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		now := types.NowDateTime()
		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{
			{Method: core.AuthSessionMethodPassword, Time: now.Add(-time.Minute)},
			{Method: core.AuthSessionMethodPassword, Time: now},
		})

		oauth2ExpectRedirect(t, b.authorize("users", "app", nil), oauth2TestPages+"/login/mfa?", map[string]string{"auth_state": "*"})
	})

	t.Run("MFA rule not matching the actor -> code", func(t *testing.T) {
		app, user := setup(t, func(c *core.Collection) {
			c.MFA.Rule = "email = 'missing@example.com'"
		})
		defer app.Cleanup()

		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}})

		b.expectCode(b.authorize("users", "app", nil), oauth2TestIssuer)
	})

	t.Run("MFA disabled -> code", func(t *testing.T) {
		app, user := setup(t, func(c *core.Collection) {
			c.MFA.Enabled = false
		})
		defer app.Cleanup()

		b, _ := stubSSO(t, app, user, []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}})

		b.expectCode(b.authorize("users", "app", map[string]string{"prompt": "none"}), oauth2TestIssuer)
	})
}

func TestOAuth2AttackOpenRedirects(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	// unregistered redirect_uri variants (no redirect at all, the error is rendered)
	for _, uri := range []string{
		"https://evil.example.com/callback",
		oauth2TestRedirectURI + "/../evil",
		oauth2TestRedirectURI + "?x=1",
		strings.Replace(oauth2TestRedirectURI, "https://", "http://", 1),
		"https://example.com.evil.com/callback",
		"https://example.com@evil.com/callback",
	} {
		res, _ := b.get(oauth2AuthorizeURL("users", "app", map[string]string{"redirect_uri": uri}))
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Fatalf("%s: expected error page without redirect, got %d %q", uri, res.StatusCode, res.Header.Get("Location"))
		}
	}

	// unregistered post_logout_redirect_uri
	res, _ := b.get("/oauth2/users/logout?client_id=app&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com"))
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("Expected post_logout_redirect_uri error page, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	// post_logout_redirect_uri without client
	res, _ = b.get("/oauth2/users/logout?post_logout_redirect_uri=" + url.QueryEscape(oauth2TestLogoutURI))
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("Expected post_logout_redirect_uri without client error page, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	// the login page "error" param is never reflected
	handle := b.startLogin("users", "app", nil)
	_, body := b.get("/oauth2/users/login?auth_state=" + url.QueryEscape(handle) + "&error=" + url.QueryEscape("<b>evil</b> call +1-555"))
	if strings.Contains(body, "evil") || strings.Contains(body, "555") {
		t.Fatal("Expected the error param not to be reflected")
	}

	// the step redirects are always same-origin paths (no AppURL/Host based absolute URLs)
	res = b.loginPassword("users", "test@example.com", "wrong")
	if loc := res.Header.Get("Location"); loc != "" && !strings.HasPrefix(loc, "/oauth2/users/") {
		t.Fatalf("Unexpected step redirect %q", loc)
	}
}

func TestOAuth2AttackIssuerMixUp(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	// a users client at the _superusers issuer
	res, _ := b.get(oauth2AuthorizeURL(core.CollectionNameSuperusers, "app", nil))
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("Expected unknown client error page, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	// a third-party client of the _superusers issuer can't even be registered
	oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	su3p := core.NewOAuth2Client(app)
	su3p.SetName("su3p")
	su3p.SetClientId("su3p")
	su3p.SetType(core.OAuth2ClientTypePublic)
	su3p.SetCollectionRef(superusers.Id)
	su3p.SetRedirectURIs([]string{oauth2TestRedirectURI})
	su3p.SetScopes([]string{"openid"})
	if err := app.Save(su3p); err == nil {
		t.Fatal("Expected the _superusers third-party client to be rejected")
	}

	// a users code exchanged at another issuer
	b.startLogin("users", "app", nil)
	code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	res, data := b.exchange("clients", "app", code, nil)
	if res.StatusCode != http.StatusUnauthorized || data["error"] != "invalid_client" {
		t.Fatalf("Expected invalid_client at another issuer, got %d %v", res.StatusCode, data)
	}

	res, data = b.exchange("clients", "other", code, nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant with another issuer client, got %d %v", res.StatusCode, data)
	}

	// the code is still usable by its own client and issuer (the failed attempts didn't consume it)
	res, data = b.exchange("users", "app", code, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected successful exchange, got %d %v", res.StatusCode, data)
	}

	// the users SSO cookie is not reused by the clients issuer
	res, _ = b.get(oauth2AuthorizeURL("clients", "other", nil))
	oauth2ExpectRedirect(t, res, "/oauth2/clients/login?", map[string]string{"auth_state": "*"})
}

func TestOAuth2AttackPromptAndMaxAge(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name      string
		authTime  time.Duration // root auth time offset
		params    map[string]string
		expectSSO bool
		expectErr string
	}{
		{"no prompt", 0, nil, true, ""},
		{"prompt=login", 0, map[string]string{"prompt": "login"}, false, ""},
		{"prompt=select_account", 0, map[string]string{"prompt": "select_account"}, false, ""},
		{"prompt=login consent", 0, map[string]string{"prompt": "login consent"}, false, ""},
		{"max_age=0", -time.Second, map[string]string{"max_age": "0"}, false, ""},
		{"max_age exceeded", -2 * time.Hour, map[string]string{"max_age": "3600"}, false, ""},
		{"max_age satisfied", -time.Minute, map[string]string{"max_age": "3600"}, true, ""},
		{"negative max_age", 0, map[string]string{"max_age": "-1"}, false, "invalid_request"},
		{"prompt=none with max_age exceeded", -2 * time.Hour, map[string]string{"prompt": "none", "max_age": "60"}, false, "login_required"},
		{"prompt=none login", 0, map[string]string{"prompt": "none login"}, false, "invalid_request"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app := oauth2AttackApp(t)

			record := oauth2FindRecord(t, app, "users", "test@example.com")
			cookie, _ := oauth2StubSSO(t, app, record, types.NowDateTime().Add(s.authTime))

			b := newOAuth2Browser(t, app)
			res, _ := b.do(http.MethodGet, oauth2AuthorizeURL("users", "app", s.params), "", map[string]string{"Cookie": cookie})

			switch {
			case s.expectErr != "":
				b.expectError(res, s.expectErr)
			case s.expectSSO:
				b.expectCode(res, oauth2TestIssuer)
			default:
				oauth2ExpectRedirect(t, res, "/oauth2/users/login?", map[string]string{"auth_state": "*"})
			}
		})
	}
}

const oauth2TestDashboardCallback = "http://localhost:8090/_/"

func TestOAuth2DashboardClientRedirectValidation(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name        string
		redirectURI string
		appURL      string
		host        string
		expectPage  bool // error page (aka. no redirect) instead of the login page
	}{
		{"same origin callback", oauth2TestDashboardCallback, "", "", false},
		{"request host callback with different app url", "http://internal.local:8090/_/", "https://example.com", "internal.local:8090", false},
		{"app url callback with different request host", "https://example.com/_/", "https://example.com", "internal.local:8090", false},
		{"other host (open redirect)", "https://evil.example.com/_/", "", "", true},
		{"other host with app url", "https://evil.example.com/_/", "https://example.com", "", true},
		{"userinfo trick", "http://localhost:8090@evil.example.com/_/", "", "", true},
		{"query", oauth2TestDashboardCallback + "?next=https://evil.example.com", "", "", true},
		{"fragment", oauth2TestDashboardCallback + "#/evil", "", "", true},
		{"other path", "http://localhost:8090/api/", "", "", true},
		{"scheme relative", "//evil.example.com/_/", "", "", true},
		{"non http scheme", "javascript:alert(1)//localhost:8090/_/", "", "", true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			if s.appURL != "" {
				app.Settings().Meta.AppURL = s.appURL
			}

			b := newOAuth2Browser(t, app)

			headers := map[string]string{}
			if s.host != "" {
				headers["Host"] = s.host
			}

			authorizeURL := oauth2AuthorizeURL(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
				"redirect_uri": s.redirectURI,
			})

			req := authorizeURL
			res, body := b.do(http.MethodGet, req, "", headers)

			if s.expectPage {
				if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" || !strings.Contains(body, "The redirect_uri is not registered for the client.") {
					t.Fatalf("Expected error page without redirect, got %d %q", res.StatusCode, res.Header.Get("Location"))
				}
				return
			}

			if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/oauth2/_superusers/login?auth_state=") {
				t.Fatalf("Expected login redirect, got %d %q %s", res.StatusCode, res.Header.Get("Location"), body)
			}
		})
	}
}

func TestOAuth2DashboardClientRedirectSchemeValidation(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name         string
		redirectURI  string
		trustedProxy bool
		proto        string
		expectLogin  bool
	}{
		{"http request -> http callback", "http://dash.local:8090/_/", false, "", true},
		{"http request -> https callback", "https://dash.local:8090/_/", false, "", false},
		{"untrusted forwarded https -> https callback", "https://dash.local:8090/_/", false, "https", false},
		{"trusted forwarded https -> https callback", "https://dash.local:8090/_/", true, "https", true},
		{"trusted forwarded https -> http callback (downgrade)", "http://dash.local:8090/_/", true, "https", false},
		{"trusted forwarded http -> http callback", "http://dash.local:8090/_/", true, "http", true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			app.Settings().Meta.AppURL = "https://example.com"
			if s.trustedProxy {
				app.Settings().TrustedProxy.Headers = []string{"X-Forwarded-For"}
			}

			b := newOAuth2Browser(t, app)

			headers := map[string]string{"Host": "dash.local:8090"}
			if s.proto != "" {
				headers["X-Forwarded-Proto"] = s.proto
			}

			authorizeURL := oauth2AuthorizeURL(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
				"redirect_uri": s.redirectURI,
			})

			res, body := b.do(http.MethodGet, authorizeURL, "", headers)

			isLogin := res.StatusCode == http.StatusFound && strings.Contains(res.Header.Get("Location"), "/oauth2/_superusers/login?auth_state=")
			if isLogin != s.expectLogin {
				t.Fatalf("Expected login redirect %v, got %d %q %s", s.expectLogin, res.StatusCode, res.Header.Get("Location"), body)
			}
			if !s.expectLogin && res.Header.Get("Location") != "" {
				t.Fatalf("Expected no redirect for a rejected redirect_uri, got %q", res.Header.Get("Location"))
			}
		})
	}
}

func TestOAuth2DashboardFlowWithDifferentAppURL(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// the dashboard is accessed with a host different from the AppURL
	// (e.g. the default AppURL with a server IP or a reverse proxy host)
	app.Settings().Meta.AppURL = "https://example.com"

	b := newOAuth2Browser(t, app)
	b.host = "internal.local:8090"

	callback := "http://internal.local:8090/_/"

	// the hosted pages are same-origin (the flow cookies are bound to the request host)
	b.startLogin(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
		"redirect_uri": callback,
		"scope":        "openid email",
	})
	if !strings.Contains(b.lastHTML, `action="/oauth2/_superusers/login/password"`) || strings.Contains(b.lastHTML, "https://example.com/oauth2") {
		t.Fatalf("Expected same-origin hosted page form actions, got\n%s", b.lastHTML)
	}

	res := b.loginPassword(core.CollectionNameSuperusers, "test@example.com", "1234567890")
	query := oauth2ExpectRedirect(t, res, callback+"?", map[string]string{
		"code": "*",
		// the issuer identifier is still the AppURL based one
		"iss": "https://example.com/oauth2/_superusers",
	})

	res, data := b.exchange(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, query.Get("code"), map[string]string{
		"redirect_uri": callback,
	})
	b.expectStatus(res, "", http.StatusOK)
	if token, _ := data["access_token"].(string); token == "" {
		t.Fatalf("Expected access token, got %v", data)
	}
}

func TestOAuth2DashboardFlow(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	b := newOAuth2Browser(t, app)

	params := map[string]string{
		"redirect_uri": oauth2TestDashboardCallback,
		"scope":        "openid email",
	}

	// login (first-party -> no consent)
	b.startLogin(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, params)
	res := b.loginPassword(core.CollectionNameSuperusers, "test@example.com", "1234567890")
	query := oauth2ExpectRedirect(t, res, oauth2TestDashboardCallback+"?", map[string]string{
		"code":  "*",
		"state": "test_state",
		"iss":   "http://localhost:8090/oauth2/_superusers",
	})

	// code exchange
	res, data := b.exchange(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, query.Get("code"), map[string]string{
		"redirect_uri": oauth2TestDashboardCallback,
	})
	b.expectStatus(res, "", http.StatusOK)

	accessToken, _ := data["access_token"].(string)
	refreshToken, _ := data["refresh_token"].(string)
	idToken, _ := data["id_token"].(string)
	if accessToken == "" || refreshToken == "" || idToken == "" {
		t.Fatalf("Expected access, refresh and id tokens, got %v", data)
	}

	claims, _ := security.ParseUnverifiedJWT(accessToken)
	if claims[core.TokenClaimOAuth2ClientId] != core.OAuth2DashboardClientId {
		t.Fatalf("Expected pb_dashboard cid, got %v", claims)
	}

	// superuser API access (first-party -> not restricted by the token guard)
	res, body := b.do(http.MethodGet, "/api/collections/_oauth2Clients/records", "", map[string]string{"Authorization": accessToken})
	b.expectStatus(res, body, http.StatusOK)

	// refresh
	res, data = b.tokenRequest(core.CollectionNameSuperusers, map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     core.OAuth2DashboardClientId,
		"refresh_token": refreshToken,
	})
	b.expectStatus(res, "", http.StatusOK)
	refreshedToken, _ := data["access_token"].(string)
	if refreshedToken == "" || data["refresh_token"] == refreshToken {
		t.Fatalf("Expected rotated tokens, got %v", data)
	}

	// impersonation of a users record (token exchange with the dashboard client)
	res, data = b.tokenRequest("users", map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"client_id":          core.OAuth2DashboardClientId,
		"subject_token":      "4q1xlclmfloku33",
		"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
		"actor_token":        refreshedToken,
		"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
	})
	b.expectStatus(res, "", http.StatusOK)
	impersonated, _ := data["access_token"].(string)
	impClaims, _ := security.ParseUnverifiedJWT(impersonated)
	act, _ := impClaims["act"].(map[string]any)
	superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
	if impClaims["id"] != "4q1xlclmfloku33" || impClaims["cid"] != core.OAuth2DashboardClientId || act["sub"] != superuser.Id {
		t.Fatalf("Unexpected impersonation claims %v", impClaims)
	}
	if record, err := app.FindAuthRecordByToken(impersonated, core.TokenTypeAuth); err != nil || record.Id != "4q1xlclmfloku33" {
		t.Fatalf("Expected valid impersonation token, got %v", err)
	}

	// a non-dashboard client of another issuer can't be used cross-issuer
	oauth2StubClient(t, app, core.CollectionNameSuperusers, "staff_other", oauth2FirstParty, func(c *core.OAuth2Client) { c.SetScopes([]string{"openid"}) })
	res, data = b.tokenRequest("users", map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"client_id":          "staff_other",
		"subject_token":      "4q1xlclmfloku33",
		"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
		"actor_token":        refreshedToken,
		"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
	})
	if res.StatusCode != http.StatusUnauthorized || data["error"] != "invalid_client" {
		t.Fatalf("Expected invalid_client, got %d %v", res.StatusCode, data)
	}

	// the dashboard client can't be used for the other grants of another issuer
	res, data = b.tokenRequest("users", map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     core.OAuth2DashboardClientId,
		"refresh_token": refreshToken,
	})
	if res.StatusCode != http.StatusUnauthorized || data["error"] != "invalid_client" {
		t.Fatalf("Expected invalid_client, got %d %v", res.StatusCode, data)
	}

	// logout with id_token_hint back to the dashboard
	res, _ = b.get("/oauth2/_superusers/logout?id_token_hint=" + url.QueryEscape(idToken) + "&post_logout_redirect_uri=" + url.QueryEscape(oauth2TestDashboardCallback) + "&state=bye")
	oauth2ExpectRedirect(t, res, oauth2TestDashboardCallback+"?", map[string]string{"state": "bye"})

	if _, err := app.FindAuthRecordByToken(refreshedToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the dashboard token to be invalid after logout")
	}

	// open redirect attempt on logout
	res, _ = b.get("/oauth2/_superusers/logout?id_token_hint=" + url.QueryEscape(idToken) + "&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com/_/"))
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("Expected 400 without redirect, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}
