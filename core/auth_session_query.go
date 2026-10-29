package core

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// FindAuthSessionById returns a single AuthSession model by its id.
func (app *BaseApp) FindAuthSessionById(id string) (*AuthSession, error) {
	if id == "" {
		return nil, errors.New("missing auth session id")
	}

	return app.findAuthSessionByExpr(dbx.HashExp{"id": id})
}

// FindAuthSessionByHandle returns a single AuthSession model whose
// opaque "auth_state" handle hash matches with the provided plain handle.
//
// Note that the returned session could be expired or in a terminal status.
func (app *BaseApp) FindAuthSessionByHandle(plainHandle string) (*AuthSession, error) {
	return app.findAuthSessionByHashField("handleHash", plainHandle)
}

// FindAuthSessionByCode returns a single AuthSession model whose
// authorization code hash matches with the provided plain code.
//
// Note that the returned session could be expired, with already consumed code or in a terminal status.
func (app *BaseApp) FindAuthSessionByCode(plainCode string) (*AuthSession, error) {
	return app.findAuthSessionByHashField("codeHash", plainCode)
}

// FindAuthSessionByRefreshToken returns a single AuthSession model
// whose current refresh token hash matches with the provided plain refresh token.
//
// Note that the returned session could be expired or in a terminal status.
func (app *BaseApp) FindAuthSessionByRefreshToken(plainToken string) (*AuthSession, error) {
	return app.findAuthSessionByHashField("refreshTokenHash", plainToken)
}

// FindAuthSessionByPrevRefreshToken returns a single AuthSession model
// whose previous (aka. already rotated) refresh token hash matches with
// the provided plain refresh token.
//
// It could be used for refresh token reuse detection.
func (app *BaseApp) FindAuthSessionByPrevRefreshToken(plainToken string) (*AuthSession, error) {
	return app.findAuthSessionByHashField("prevRefreshTokenHash", plainToken)
}

func (app *BaseApp) findAuthSessionByHashField(field string, plain string) (*AuthSession, error) {
	if plain == "" {
		return nil, errors.New("missing " + field + " value")
	}

	return app.findAuthSessionByExpr(dbx.HashExp{field: security.SHA256(plain)})
}

func (app *BaseApp) findAuthSessionByExpr(expr dbx.Expression) (*AuthSession, error) {
	result := &AuthSession{}

	err := app.RecordQuery(CollectionNameAuthSessions).
		AndWhere(expr).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllAuthSessionsByRecord returns all AuthSession models of the provided auth record
// (in any status, ordered by their creation date DESC).
func (app *BaseApp) FindAllAuthSessionsByRecord(authRecord *Record) ([]*AuthSession, error) {
	result := []*AuthSession{}

	err := app.RecordQuery(CollectionNameAuthSessions).
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
		}).
		OrderBy("created DESC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// EndAllAuthSessionsByRecord ends all non-terminal auth sessions of the provided auth record.
//
// Returns a combined error with the failed updates.
func (app *BaseApp) EndAllAuthSessionsByRecord(authRecord *Record) error {
	return endAuthSessionsByExpr(context.Background(), app, dbx.HashExp{
		"collectionRef": authRecord.Collection().Id,
		"recordRef":     authRecord.Id,
	})
}

// EndAllAuthSessionsByClient ends all non-terminal auth sessions of the provided OAuth2 client.
//
// Returns a combined error with the failed updates.
func (app *BaseApp) EndAllAuthSessionsByClient(client *OAuth2Client) error {
	return endAuthSessionsByExpr(context.Background(), app, dbx.HashExp{"client": client.Id})
}

// preservedAuthSessionsKey is the context key of the auth sessions that must not be
// ended by the auth sessions cascades (see [WithPreservedAuthSessions]).
type preservedAuthSessionsKey struct{}

// WithPreservedAuthSessions returns a new context that instructs the auth sessions
// cascades triggered by a save with that context (e.g. the tokenKey change of a
// verified upgrade or a root session ending) to not end the specified sessions.
//
// It is used to keep alive the in-progress hosted login flow session that
// caused the cascade (all other sessions of the record still end).
//
// Example:
//
//	app.SaveWithContext(core.WithPreservedAuthSessions(ctx, flowSession.Id), record)
func WithPreservedAuthSessions(ctx context.Context, sessionIds ...string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	ids := append(slices.Clone(preservedAuthSessions(ctx)), sessionIds...)

	return context.WithValue(ctx, preservedAuthSessionsKey{}, ids)
}

func preservedAuthSessions(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}

	ids, _ := ctx.Value(preservedAuthSessionsKey{}).([]string)

	return ids
}

// endAuthSessionsByExpr ends all non-terminal auth sessions matching the provided expression
// (the cascades of each ended session are also applied) except the ones preserved
// in the provided context (see [WithPreservedAuthSessions]).
func endAuthSessionsByExpr(ctx context.Context, app App, expr dbx.Expression) error {
	if ctx == nil {
		ctx = context.Background()
	}

	sessions := []*AuthSession{}

	err := app.RecordQuery(CollectionNameAuthSessions).
		AndWhere(expr).
		AndWhere(dbx.NotIn("status", AuthSessionStatusEnded, AuthSessionStatusFailed)).
		All(&sessions)
	if err != nil {
		return err
	}

	preserved := preservedAuthSessions(ctx)

	var errs []error
	for _, s := range sessions {
		if slices.Contains(preserved, s.Id) {
			continue
		}

		// could be already ended by a cascade
		fresh, err := app.FindAuthSessionById(s.Id)
		if err != nil || fresh.IsTerminal() {
			continue
		}

		if err := fresh.End(); err != nil {
			errs = append(errs, err)
			continue
		}

		if err := app.SaveWithContext(ctx, fresh); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func deleteAuthSessionsByExpr(app App, exp dbx.HashExp) error {
	sessions, err := app.FindAllRecords(CollectionNameAuthSessions, exp)
	if err != nil {
		return err
	}

	for _, s := range sessions {
		if err := app.Delete(s); err != nil {
			return err
		}
	}

	return nil
}

// DeleteExpiredAuthSessions deletes all ended, failed and expired auth sessions.
//
// The application extensions online sessions are kept at least [applicationLaunchJtiRetention]
// after their creation (their launch token jti is the persisted replay protection).
func (app *BaseApp) DeleteExpiredAuthSessions() error {
	items := []*Record{}

	err := app.RecordQuery(CollectionNameAuthSessions).
		AndWhere(dbx.Or(
			dbx.In("status", AuthSessionStatusEnded, AuthSessionStatusFailed),
			dbx.NewExp("[[expiresAt]] < {:now}", dbx.Params{"now": types.NowDateTime()}),
		)).
		AndWhere(dbx.NewExp(
			"([[launchJti]] = '' OR [[created]] < {:launchRetention})",
			dbx.Params{"launchRetention": types.NowDateTime().Add(-applicationLaunchJtiRetention)},
		)).
		All(&items)
	if err != nil {
		return err
	}

	for _, item := range items {
		err = app.Delete(item)
		if err != nil {
			return err
		}
	}

	return nil
}

// AuthSessionOptions defines the [App.NewAuthSession] options.
type AuthSessionOptions struct {
	// Scopes is the list of the session granted scopes.
	//
	// It must be a subset of the client scopes (default to all client scopes).
	Scopes []string

	// AuthMethods is the optional list of the completed factors (aka. "amr").
	AuthMethods []AuthSessionMethod

	// Impersonator is the optional id of the staff (_superusers) record
	// on whose behalf the session is created (the access tokens will have "act" claim).
	//
	// It requires ImpersonatorSession.
	Impersonator string

	// ImpersonatorSession is the id of the active impersonator auth session
	// (required with Impersonator; the impersonation session tokens are
	// accepted only while the impersonator session is active).
	ImpersonatorSession string

	// Parent is the optional root SSO session id.
	Parent string

	// IP and UserAgent are the optional session client info.
	IP        string
	UserAgent string

	// Duration is the session duration (default to the collection AuthToken.Duration).
	Duration time.Duration
}

// CreateAuthSession creates and persists a new active auth session for the
// provided auth record and OAuth2 client (e.g. for custom auth methods,
// token exchange or tests).
//
// The returned session has already attached actor and client
// so that [AuthSession.NewAccessToken] could be called directly.
func (app *BaseApp) CreateAuthSession(authRecord *Record, client *OAuth2Client, opts AuthSessionOptions) (*AuthSession, error) {
	if authRecord == nil || !authRecord.Collection().IsAuth() {
		return nil, ErrNotAuthRecord
	}

	// the application installations tokens are issued only by the
	// {issuer}/token client_credentials grant (A-I1)
	if authRecord.Collection().Name == CollectionNameApplicationInstallations {
		return nil, errors.New("the application installations sessions could be created only with the client_credentials grant of the token endpoint")
	}

	if client == nil || client.Id == "" {
		return nil, errors.New("missing OAuth2 client")
	}

	// note: the dashboard client could be used cross-issuer only for impersonation
	crossIssuerImpersonation := opts.Impersonator != "" && client.IsDashboard()
	if !client.IsUsable() || (client.CollectionRef() != authRecord.Collection().Id && !crossIssuerImpersonation) {
		return nil, errors.New("the OAuth2 client is disabled or not registered for the auth record collection")
	}

	scopes := list.ToUniqueStringSlice(opts.Scopes)
	if len(opts.Scopes) == 0 {
		scopes = client.Scopes()
	}

	allowed := OAuth2AllowedScopes(app, authRecord.Collection())
	clientScopes := client.Scopes()
	for _, s := range scopes {
		if !slices.Contains(allowed, s) || !slices.Contains(clientScopes, s) {
			return nil, fmt.Errorf("the scope %q is not allowed for the client", s)
		}
	}

	var impersonator *Record
	if opts.Impersonator != "" {
		var err error
		impersonator, err = app.findLiveImpersonator(opts.Impersonator, opts.ImpersonatorSession)
		if err != nil {
			return nil, err
		}
	}

	duration := opts.Duration
	if duration <= 0 {
		duration = authRecord.Collection().AuthToken.DurationTime()
	}

	now := types.NowDateTime()

	session := NewAuthSession(app)
	session.Set("status", AuthSessionStatusActive)
	session.SetCollectionRef(authRecord.Collection().Id)
	session.SetClient(client.Id)
	session.SetRecordRef(authRecord.Id)
	session.SetScopesRequested(scopes)
	session.SetScopes(scopes)
	session.SetAuthMethods(opts.AuthMethods)
	session.SetAuthTime(now)
	session.BindImpersonator(impersonator, opts.ImpersonatorSession)
	session.SetParent(opts.Parent)
	session.SetIP(opts.IP)
	session.SetUserAgent(opts.UserAgent)
	session.SetLastUsedAt(now)
	session.SetExpiresAt(now.Add(duration))

	if err := app.Save(session); err != nil {
		return nil, err
	}

	if err := session.AttachActor(authRecord, client); err != nil {
		return nil, err
	}

	return session, nil
}

// findLiveImpersonator returns the staff record with the specified id if
// the provided session is its active (non-impersonation) auth session.
func (app *BaseApp) findLiveImpersonator(staffId string, staffSessionId string) (*Record, error) {
	if staffSessionId == "" {
		return nil, errors.New("missing impersonator session")
	}

	staff, err := app.FindRecordById(CollectionNameSuperusers, staffId)
	if err != nil {
		return nil, fmt.Errorf("missing impersonator staff record: %w", err)
	}

	staffSession, err := app.FindAuthSessionById(staffSessionId)
	if err != nil ||
		!staffSession.IsActive() ||
		staffSession.IsRoot() ||
		staffSession.Impersonator() != "" ||
		staffSession.RecordRef() != staff.Id ||
		staffSession.CollectionRef() != staff.Collection().Id {
		return nil, errors.New("the impersonator session is missing or not active")
	}

	return staff, nil
}

// authSessionTokenRow holds the auth session data needed for validating an auth token.
type authSessionTokenRow struct {
	Status         string                  `db:"status"`
	RecordRef      string                  `db:"recordRef"`
	CollectionRef  string                  `db:"collectionRef"`
	Parent         string                  `db:"parent"`
	Scopes         types.JSONArray[string] `db:"scopes"`
	ExpiresAt      types.DateTime          `db:"expiresAt"`
	AMR            types.JSONRaw           `db:"amr"`
	ClientId       string                  `db:"clientId"`
	ClientDisabled bool                    `db:"clientDisabled"`

	// application installations (client_credentials)
	ClientInstallationRef string                  `db:"clientInstallationRef"`
	ClientGrantTypes      types.JSONArray[string] `db:"clientGrantTypes"`
	InstallationStatus    string                  `db:"installationStatus"`
	RootExists            bool                    `db:"rootExists"`
	RootStatus            string                  `db:"rootStatus"`
	RootExpiresAt         types.DateTime          `db:"rootExpiresAt"`

	// impersonation
	Impersonator                 string         `db:"impersonator"`
	ImpersonatorKeyHash          string         `db:"impersonatorKeyHash"`
	ImpersonatorTokenKey         string         `db:"impersonatorTokenKey"`
	ImpersonatorSessionExists    bool           `db:"impersonatorSessionExists"`
	ImpersonatorSessionStatus    string         `db:"impersonatorSessionStatus"`
	ImpersonatorSessionExpiresAt types.DateTime `db:"impersonatorSessionExpiresAt"`
	ImpersonatorSessionRecordRef string         `db:"impersonatorSessionRecordRef"`
	ImpersonatorCanImpersonate   bool           `db:"impersonatorCanImpersonate"`
}

// checkAuthSessionTokenClaims checks whether the provided auth token session id points to:
//   - an active and not expired session of the provided auth record
//   - whose client exists, is not disabled and matches with the token client_id
//   - whose root SSO session (if any) is not ended or expired
//     (the sessions with "offline_access" scope survive the root ending)
//   - (application installation sessions only) a root-less client_credentials session of the
//     installation own managed client while the installation is active
//   - (application extensions online sessions only) a launch session of a staff member with an
//     installation managed client (that allows the token exchange grant) while the installation
//     is active and the staff root SSO session is active (never offline)
//   - (impersonation sessions only) whose impersonator session is still active,
//     whose impersonator record exists with unchanged tokenKey and still holds
//     the impersonate permission (Owners implicitly hold it)
//
// The session, its client, root, impersonator session, impersonator record and
// impersonator permissions are loaded with a single (primary key) join query.
func (app *BaseApp) checkAuthSessionTokenClaims(record *Record, sid string, clientId string) error {
	row := authSessionTokenRow{}

	superusersId := ""
	if superusers, err := app.FindCachedCollectionByNameOrId(CollectionNameSuperusers); err == nil {
		superusersId = superusers.Id
	}

	err := app.DB().Select(
		"s.status as status",
		"s.recordRef as recordRef",
		"s.collectionRef as collectionRef",
		"s.parent as parent",
		"s.scopes as scopes",
		"s.expiresAt as expiresAt",
		"s.amr as amr",
		"c.clientId as clientId",
		"c.disabled as clientDisabled",
		"c.applicationInstallationRef as clientInstallationRef",
		"c.grantTypes as clientGrantTypes",
		"COALESCE(ai.status, '') as installationStatus",
		"(r.id IS NOT NULL) as rootExists",
		"COALESCE(r.status, '') as rootStatus",
		"COALESCE(r.expiresAt, '') as rootExpiresAt",
		"s.impersonator as impersonator",
		"s.impersonatorKeyHash as impersonatorKeyHash",
		"COALESCE(su.tokenKey, '') as impersonatorTokenKey",
		"(i.id IS NOT NULL) as impersonatorSessionExists",
		"COALESCE(i.status, '') as impersonatorSessionStatus",
		"COALESCE(i.expiresAt, '') as impersonatorSessionExpiresAt",
		"COALESCE(i.recordRef, '') as impersonatorSessionRecordRef",
		// note: evaluated only for the impersonation sessions
		`(CASE WHEN [[s.impersonator]] = '' THEN FALSE ELSE EXISTS (
			SELECT 1 FROM {{`+CollectionNameRoleAssignments+`}} ra
			INNER JOIN {{`+CollectionNameRoles+`}} ro ON [[ro.id]] = [[ra.role]]
			WHERE [[ra.collectionRef]] = {:superusersId}
				AND [[ra.recordRef]] = [[s.impersonator]]
				AND (
					([[ro.system]] = TRUE AND [[ro.name]] = {:ownerRole}) OR
					json_extract([[ro.permissions]], '$.system.`+PermissionResourceImpersonate+`') = {:impersonateLevel}
				)
		) END) as impersonatorCanImpersonate`,
	).
		From(CollectionNameAuthSessions+" s").
		InnerJoin(CollectionNameOAuth2Clients+" c", dbx.NewExp("[[c.id]] = [[s.client]]")).
		LeftJoin(CollectionNameApplicationInstallations+" ai", dbx.NewExp("[[c.applicationInstallationRef]] != '' AND [[ai.id]] = [[c.applicationInstallationRef]]")).
		LeftJoin(CollectionNameAuthSessions+" r", dbx.NewExp("[[s.parent]] != '' AND [[r.id]] = [[s.parent]]")).
		LeftJoin(CollectionNameAuthSessions+" i", dbx.NewExp("[[s.impersonatorSession]] != '' AND [[i.id]] = [[s.impersonatorSession]]")).
		LeftJoin(CollectionNameSuperusers+" su", dbx.NewExp("[[s.impersonator]] != '' AND [[su.id]] = [[s.impersonator]]")).
		Where(dbx.HashExp{"s.id": sid}).
		Bind(dbx.Params{
			"superusersId":     superusersId,
			"ownerRole":        RoleNameOwner,
			"impersonateLevel": PermissionLevelWrite,
		}).
		Limit(1).
		One(&row)
	if err != nil {
		return fmt.Errorf("failed to load the auth token session: %w", err)
	}

	if row.RecordRef != record.Id || row.CollectionRef != record.Collection().Id {
		return errors.New("the auth token session doesn't belong to the auth record")
	}

	if row.ClientDisabled || clientId == "" || !security.Equal(row.ClientId, clientId) {
		return errors.New("the auth token session client is disabled or doesn't match")
	}

	if row.Status != AuthSessionStatusActive || !row.ExpiresAt.Time().After(time.Now()) {
		return errors.New("the auth token session is not active or has expired")
	}

	// the application installations tokens (and only them) are client_credentials tokens:
	// a root-less client_credentials session (explicitly accepted only for that method)
	// issued to the installation own managed client that still allows the grant
	// (and only while the installation is active)
	methods := []AuthSessionMethod{}
	_ = json.Unmarshal(row.AMR, &methods)
	isClientCredentials := slices.ContainsFunc(methods, func(m AuthSessionMethod) bool {
		return m.Method == AuthSessionMethodClientCredentials
	})
	isLaunch := slices.ContainsFunc(methods, func(m AuthSessionMethod) bool {
		return m.Method == AuthSessionMethodLaunch
	})
	isInstallation := record.Collection().Name == CollectionNameApplicationInstallations

	// the application extensions online tokens (actor = staff, client = the installation managed client)
	if isLaunch || (row.ClientInstallationRef != "" && !isInstallation && !isClientCredentials) {
		if !isLaunch ||
			isInstallation ||
			isClientCredentials ||
			!record.IsSuperuser() ||
			row.ClientInstallationRef == "" ||
			row.InstallationStatus != ApplicationInstallationStatusActive ||
			!slices.Contains(row.ClientGrantTypes, OAuth2GrantTypeTokenExchange) ||
			row.Impersonator != "" ||
			row.Parent == "" ||
			!row.RootExists ||
			row.RootStatus != AuthSessionStatusActive ||
			!row.RootExpiresAt.Time().After(time.Now()) {
			return errors.New("invalid application extension (launch) auth token session")
		}

		return nil
	}

	if isInstallation || isClientCredentials || row.ClientInstallationRef != "" {
		if !isInstallation ||
			!isClientCredentials ||
			row.ClientInstallationRef != record.Id ||
			row.InstallationStatus != ApplicationInstallationStatusActive ||
			!slices.Contains(row.ClientGrantTypes, OAuth2GrantTypeClientCredentials) ||
			row.Parent != "" ||
			row.Impersonator != "" {
			return errors.New("invalid application installation (client_credentials) auth token session")
		}

		return nil
	}

	if row.Parent != "" && !slices.Contains(row.Scopes, OAuth2ScopeOfflineAccess) {
		if !row.RootExists ||
			row.RootStatus != AuthSessionStatusActive ||
			!row.RootExpiresAt.Time().After(time.Now()) {
			return errors.New("the auth token root session has ended")
		}
	}

	if row.Impersonator != "" {
		if !row.ImpersonatorSessionExists ||
			row.ImpersonatorSessionRecordRef != row.Impersonator ||
			row.ImpersonatorSessionStatus != AuthSessionStatusActive ||
			!row.ImpersonatorSessionExpiresAt.Time().After(time.Now()) {
			return errors.New("the auth token impersonator session has ended")
		}

		if row.ImpersonatorTokenKey == "" || !validateImpersonatorTokenKey(row.ImpersonatorKeyHash, row.ImpersonatorTokenKey) {
			return errors.New("the auth token impersonator is missing or its tokenKey has changed")
		}

		if !row.ImpersonatorCanImpersonate {
			return errors.New("the auth token impersonator is no longer allowed to impersonate")
		}
	}

	return nil
}

// IsAuthSessionRootAlive reports whether the root SSO session of the provided
// session is still active (the sessions with "offline_access" scope and
// the sessions without root, e.g. programmatic ones, are not bound to a root).
func (app *BaseApp) IsAuthSessionRootAlive(session *AuthSession) bool {
	if session.Parent() == "" || session.HasScope(OAuth2ScopeOfflineAccess) {
		return true
	}

	root, err := app.FindAuthSessionById(session.Parent())

	return err == nil && root.IsRoot() && root.IsActive()
}

// EndAuthSession ends the provided auth session (and its children)
// because of the provided reason (e.g. a detected security issue).
//
// It is no-op if the session is missing or already ended.
func (app *BaseApp) EndAuthSession(session *AuthSession, reason string) error {
	app.Logger().Warn(
		reason+" detected, ending the related auth session",
		"sessionId", session.Id,
		"clientId", session.Client(),
		"recordId", session.RecordRef(),
	)

	fresh, err := app.FindAuthSessionById(session.Id)
	if err != nil || fresh.IsTerminal() {
		return nil
	}

	if err := fresh.End(); err != nil {
		return nil
	}

	return app.Save(fresh)
}
