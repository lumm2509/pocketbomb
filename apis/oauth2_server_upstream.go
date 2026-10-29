package apis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/security"
	"golang.org/x/oauth2"
)

// GET|POST /api/oauth2-redirect
//
// oauth2ServerUpstreamRedirect reads the upstream OAuth2 provider redirect data
// (query or form_post body) and handles it as hosted login flow callback.
func oauth2ServerUpstreamRedirect(e *core.RequestEvent) error {
	data := oauth2RedirectData{}

	if e.Request.Method == http.MethodPost {
		if err := oauth2BindBody(e, &data); err != nil {
			return e.BadRequestError("Invalid OAuth2 redirect data.", err)
		}
	} else {
		query := e.Request.URL.Query()
		data.State = query.Get("state")
		data.Code = query.Get("code")
		data.Error = query.Get("error")
	}

	if !strings.HasPrefix(data.State, oauth2UpstreamStatePrefix) {
		return e.BadRequestError("Invalid or expired sign-in request. Please go back to the application and try again.", nil)
	}

	return oauth2ServerUpstreamCallback(e, data)
}

// oauth2ServerUpstreamCallback handles the upstream OAuth2 provider callback
// of a hosted login flow (GET or form_post POST to /api/oauth2-redirect).
//
// The callback could be a cross-site POST (e.g. Apple form_post) and therefore
// the Lax binding cookie is not checked here. Because of this the callback only
// resolves (links or creates) the upstream record and stores it as pending result
// in the flow session. The flow handle is rotated and the browser is redirected to
// the GET {issuer}/login/continue step which checks the binding cookie and only
// then applies the pending result as factor (aka. identifies the actor).
func oauth2ServerUpstreamCallback(e *core.RequestEvent, data oauth2RedirectData) error {
	invalidCallback := func(collection *core.Collection, err error) error {
		e.App.Logger().Debug("Invalid hosted login upstream OAuth2 callback", "error", err)

		if collection == nil {
			return e.BadRequestError("Invalid or expired sign-in request. Please go back to the application and try again.", err)
		}

		return oauth2RenderInvalidFlowPage(e, collection, err)
	}

	sessionId, secret, _ := strings.Cut(strings.TrimPrefix(data.State, oauth2UpstreamStatePrefix), ".")
	if sessionId == "" || secret == "" || len(data.State) > 255 {
		return invalidCallback(nil, errors.New("malformed upstream state"))
	}

	session, err := e.App.FindAuthSessionById(sessionId)
	if err != nil {
		return invalidCallback(nil, err)
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(session.CollectionRef())
	if err != nil || !collection.IsAuth() {
		return invalidCallback(nil, errors.New("missing auth session collection"))
	}

	providerName := session.UpstreamProvider()
	codeVerifier := session.UpstreamCodeVerifier()

	if providerName == "" ||
		session.Status() != core.AuthSessionStatusPending ||
		!session.ValidateUpstreamState(secret) {
		return invalidCallback(collection, errors.New("invalid upstream state or session status"))
	}

	flow, err := loadOAuth2FlowSession(e, collection, session, "", false)
	if err != nil {
		return invalidCallback(collection, err)
	}

	// the upstream state is single use and the handle is rotated
	// so that only the browser that receives the redirect could continue
	flow.handle = security.RandomString(oauth2HandleLength)
	flow.session.SetHandle(flow.handle)
	flow.session.SetUpstreamResult("")
	if err := e.App.Save(flow.session); err != nil {
		return invalidCallback(collection, err)
	}

	failure := func(err error) error {
		e.App.Logger().Debug("Failed hosted login upstream OAuth2 factor", "provider", providerName, "error", err)

		flow.session.SetUpstream("", "", "")
		if err := e.App.Save(flow.session); err != nil {
			e.App.Logger().Warn("Failed to clear the upstream OAuth2 step", "error", err)
		}

		path := "/login"
		if flow.record != nil && flow.session.MFARequired() {
			path = "/login/mfa"
		}

		return e.Redirect(oauth2RedirectStatus(e), flow.stepURL(e.App, path)+"&error=upstream")
	}

	if data.Error != "" || data.Code == "" {
		return failure(errors.New("upstream error or missing code: " + data.Error))
	}

	if !oauth2ProvidersAllowed(collection) {
		return failure(errors.New("upstream OAuth2 providers are not allowed"))
	}

	authUser, err := oauth2FetchUpstreamUser(e, collection, providerName, data.Code, codeVerifier)
	if err != nil {
		return failure(err)
	}

	// Apple returns the user name only with the first redirect form data
	if providerName == auth.NameApple && authUser.Name == "" && data.AppleUser != "" {
		if name, err := parseAppleRedirectName(data.AppleUser); err == nil {
			authUser.Name = name
		}
	}

	e.Set(core.RequestEventKeyInfoContext, core.RequestInfoContextOAuth2)

	record, err := oauth2ResolveUpstreamRecord(e, flow, providerName, authUser)
	if err != nil {
		return failure(err)
	}

	// store only the resolved record as pending result
	// (it is applied as factor by the continue step after the binding check)
	flow.session.SetUpstreamResult(record.Id)
	if err := e.App.Save(flow.session); err != nil {
		return failure(err)
	}

	return e.Redirect(oauth2RedirectStatus(e), flow.stepURL(e.App, "/login/continue"))
}

// oauth2FetchUpstreamUser exchanges the upstream authorization code and fetches the upstream OAuth2 user.
func oauth2FetchUpstreamUser(e *core.RequestEvent, collection *core.Collection, providerName string, code string, codeVerifier string) (*auth.AuthUser, error) {
	config, ok := collection.OAuth2.GetProviderConfig(providerName)
	if !ok {
		return nil, errors.New("missing or disabled upstream provider " + providerName)
	}

	provider, err := config.InitProvider()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 30*time.Second)
	defer cancel()

	provider.SetContext(ctx)
	provider.SetRedirectURL(oauth2UpstreamRedirectURL(e.App))

	var opts []oauth2.AuthCodeOption
	if codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	token, err := provider.FetchToken(code, opts...)
	if err != nil {
		return nil, err
	}

	authUser, err := provider.FetchAuthUser(token)
	if err != nil {
		return nil, err
	}

	if authUser == nil || authUser.Id == "" {
		return nil, errors.New("missing upstream OAuth2 user id")
	}

	return authUser, nil
}

// oauth2ResolveUpstreamRecord finds, links or creates the auth record of the upstream OAuth2 user
// (using the same logic as the removed vanilla OAuth2 auth endpoint but without fallback linking to an
// authenticated record because a partially authenticated flow must not link new providers).
//
// If the flow actor is already identified (aka. MFA) the upstream user must resolve to the same
// record and no new record is created.
func oauth2ResolveUpstreamRecord(e *core.RequestEvent, flow *oauth2Flow, providerName string, authUser *auth.AuthUser) (*core.Record, error) {
	record, externalAuth, err := findOAuth2UpstreamRecord(e.App, flow.collection, providerName, authUser)
	if err != nil {
		return nil, err
	}

	if flow.record != nil {
		if record == nil || record.Id != flow.record.Id {
			return nil, errOAuth2FactorMismatch
		}
	}

	// the hosted pages requests are always handled as guests
	originalAuth := e.Auth
	e.Auth = nil
	defer func() {
		e.Auth = originalAuth
	}()

	// note: the pre-hijacking protections and the verified upgrade could rotate the record tokenKey
	// which ends all of its sessions except the current in-progress flow
	ctx := core.WithPreservedAuthSessions(e.Request.Context(), flow.session.Id)

	saved, err := saveOAuth2UpstreamRecord(ctx, e, flow.collection, providerName, authUser, nil, record, externalAuth)
	if err != nil {
		return nil, err
	}

	if saved == nil {
		return nil, errors.New("failed to resolve the upstream OAuth2 record")
	}

	return saved, nil
}

type oauth2RedirectData struct {
	State string `form:"state" json:"state"`
	Code  string `form:"code" json:"code"`
	Error string `form:"error" json:"error,omitempty"`

	// returned by Apple only
	AppleUser string `form:"user" json:"-"`
}

// parseAppleRedirectName extracts the first and last name from the
// Apple redirect "user" form field (it is sent only on the first authorization).
func parseAppleRedirectName(serializedNameData string) (string, error) {
	if serializedNameData == "" || len(serializedNameData) > 5000 {
		return "", nil
	}

	// https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms#Handle-the-response
	extracted := struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}{}
	if err := json.Unmarshal([]byte(serializedNameData), &extracted); err != nil {
		return "", err
	}

	fullName := extracted.Name.FirstName + " " + extracted.Name.LastName

	// truncate just in case to prevent storing large strings in memory
	if len(fullName) > 150 {
		fullName = fullName[:150]
	}

	return strings.TrimSpace(fullName), nil
}
