package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	"github.com/spf13/cast"
)

func newPendingAuthSession(t testing.TB, app core.App, client *core.OAuth2Client) *core.AuthSession {
	t.Helper()

	s := core.NewAuthSession(app)
	s.SetCollectionRef(client.CollectionRef())
	s.SetClient(client.Id)
	s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}

	return s
}

func TestNewAuthSession(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	s := core.NewAuthSession(app)

	if s.Collection().Name != core.CollectionNameAuthSessions {
		t.Fatalf("Expected record with %q collection, got %q", core.CollectionNameAuthSessions, s.Collection().Name)
	}

	if s.Status() != core.AuthSessionStatusPending {
		t.Fatalf("Expected pending status, got %q", s.Status())
	}

	if s.MaxAge() != -1 {
		t.Fatalf("Expected unset (-1) maxAge, got %d", s.MaxAge())
	}

	// the hash and secret fields must be hidden
	for _, name := range []string{"handleHash", "bindingHash", "upstreamState", "upstreamCodeVerifier", "codeHash", "refreshTokenHash", "prevRefreshTokenHash", "ssoSecretHash"} {
		f := s.Collection().Fields.GetByName(name)
		if f == nil || !f.GetHidden() {
			t.Errorf("Expected hidden %q field", name)
		}
	}

	// all API rules are nil (superusers only)
	c := s.Collection()
	if c.ListRule != nil || c.ViewRule != nil || c.CreateRule != nil || c.UpdateRule != nil || c.DeleteRule != nil {
		t.Fatal("Expected all _authSessions API rules to be nil")
	}
}

func TestAuthSessionTransitions(t *testing.T) {
	t.Parallel()

	legal := map[string][]string{
		core.AuthSessionStatusPending:       {core.AuthSessionStatusAuthenticated, core.AuthSessionStatusFailed, core.AuthSessionStatusEnded},
		core.AuthSessionStatusAuthenticated: {core.AuthSessionStatusAuthorized, core.AuthSessionStatusFailed, core.AuthSessionStatusEnded},
		core.AuthSessionStatusAuthorized:    {core.AuthSessionStatusActive, core.AuthSessionStatusFailed, core.AuthSessionStatusEnded},
		core.AuthSessionStatusActive:        {core.AuthSessionStatusEnded},
		core.AuthSessionStatusEnded:         {},
		core.AuthSessionStatusFailed:        {},
	}

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := stubOAuth2Client(t, app, "users", "transitions")

	for _, from := range core.AuthSessionStatuses {
		for _, to := range core.AuthSessionStatuses {
			expectOk := slices.Contains(legal[from], to)

			t.Run(from+"->"+to, func(t *testing.T) {
				// in-memory transition
				s := core.NewAuthSession(app)
				s.Set("status", from)

				if s.CanTransitionTo(to) != expectOk {
					t.Fatalf("Expected CanTransitionTo %v", expectOk)
				}

				err := s.TransitionTo(to)
				if expectOk {
					if err != nil || s.Status() != to {
						t.Fatalf("Expected successful transition, got %v (%q)", err, s.Status())
					}
				} else {
					if !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
						t.Fatalf("Expected ErrInvalidAuthSessionTransition, got %v", err)
					}
					if s.Status() != from {
						t.Fatalf("Expected the status to remain %q, got %q", from, s.Status())
					}
				}

				// persisted transition (the change is validated even if the status is set directly)
				persisted := newPendingAuthSession(t, app, client)
				if from != core.AuthSessionStatusPending {
					// raw update to stub the initial status
					// (even SaveNoValidate checks the transition against the persisted status)
					_, err := app.DB().Update(core.CollectionNameAuthSessions, dbx.Params{"status": from}, dbx.HashExp{"id": persisted.Id}).Execute()
					if err != nil {
						t.Fatal(err)
					}
					persisted, err = app.FindAuthSessionById(persisted.Id)
					if err != nil {
						t.Fatal(err)
					}
				}

				persisted.Set("status", to)
				saveErr := app.Save(persisted)

				if expectOk || from == to {
					if saveErr != nil {
						t.Fatalf("Expected the save to succeed, got %v", saveErr)
					}
				} else {
					if saveErr == nil || !strings.Contains(saveErr.Error(), "status") {
						t.Fatalf("Expected status validation error, got %v", saveErr)
					}
				}
			})
		}
	}

	t.Run("named transition helpers", func(t *testing.T) {
		s := core.NewAuthSession(app)

		steps := []struct {
			fn       func() error
			expected string
		}{
			{s.MarkAuthenticated, core.AuthSessionStatusAuthenticated},
			{s.MarkAuthorized, core.AuthSessionStatusAuthorized},
			{s.MarkActive, core.AuthSessionStatusActive},
			{s.End, core.AuthSessionStatusEnded},
		}
		for _, step := range steps {
			if err := step.fn(); err != nil || s.Status() != step.expected {
				t.Fatalf("Expected %q, got %q (%v)", step.expected, s.Status(), err)
			}
		}

		if err := s.Fail(); err == nil {
			t.Fatal("Expected ended -> failed to fail")
		}
		if !s.IsTerminal() {
			t.Fatal("Expected terminal session")
		}

		s2 := core.NewAuthSession(app)
		if err := s2.MarkActive(); err == nil {
			t.Fatal("Expected pending -> active (skipping steps) to fail")
		}
		if err := s2.MarkAuthorized(); err == nil {
			t.Fatal("Expected pending -> authorized (skipping steps) to fail")
		}
	})
}

func TestAuthSessionInitialStatusValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := stubOAuth2Client(t, app, "users", "initial")

	for _, status := range core.AuthSessionStatuses {
		t.Run(status, func(t *testing.T) {
			s := core.NewAuthSession(app)
			s.SetCollectionRef(client.CollectionRef())
			s.SetClient(client.Id)
			s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
			s.Set("status", status)

			err := app.Save(s)

			expectOk := status == core.AuthSessionStatusPending || status == core.AuthSessionStatusActive
			if expectOk && err != nil {
				t.Fatalf("Expected new %q session to be valid, got %v", status, err)
			}
			if !expectOk && err == nil {
				t.Fatalf("Expected new %q session to be invalid", status)
			}
		})
	}
}

func TestAuthSessionValidateHook(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user1, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user2, err := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	clientsUser, err := app.FindAuthRecordByEmail("clients", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	usersClient := stubOAuth2Client(t, app, "users", "users_client")

	scenarios := []struct {
		name           string
		session        func() *core.AuthSession
		expectedErrors []string
	}{
		{
			"empty",
			func() *core.AuthSession {
				return core.NewAuthSession(app)
			},
			[]string{"collectionRef", "expiresAt"},
		},
		{
			"non-root session without client",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"client"},
		},
		{
			"root SSO session with client",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetClient(usersClient.Id)
				s.SetSSOSecret("secret")
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"client"},
		},
		{
			"root SSO session with flow handle, code, token family and parent",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetSSOSecret("secret")
				s.SetHandle("handle")
				s.SetCode("code", types.NowDateTime().Add(time.Minute))
				s.SetRefreshToken("refresh")
				s.RotateRefreshToken("refresh2")
				s.SetParent("abc")
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"handleHash", "codeHash", "refreshTokenHash", "prevRefreshTokenHash", "parent"},
		},
		{
			"valid root SSO session without client",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.Set("status", core.AuthSessionStatusActive)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetRecordRef(user1.Id)
				s.SetSSOSecret("secret")
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{},
		},
		{
			"missing pending upstream record",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetClient(usersClient.Id)
				s.SetUpstreamResult("missing")
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"upstreamRecordRef"},
		},
		{
			"non-auth collection",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef("demo1")
				s.SetClient(usersClient.Id)
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"collectionRef", "client"},
		},
		{
			"client of another collection",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(clientsUser.Collection().Id)
				s.SetClient(usersClient.Id)
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"client"},
		},
		{
			"missing actor record",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetClient(usersClient.Id)
				s.SetRecordRef("missing")
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{"recordRef"},
		},
		{
			"pending session without actor",
			func() *core.AuthSession {
				s := core.NewAuthSession(app)
				s.SetCollectionRef(user1.Collection().Id)
				s.SetClient(usersClient.Id)
				s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
				return s
			},
			[]string{},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			tests.TestValidationErrors(t, app.Validate(s.session()), s.expectedErrors)
		})
	}

	t.Run("the actor of an identified session cannot be changed", func(t *testing.T) {
		s := newPendingAuthSession(t, app, usersClient)

		s.SetRecordRef(user1.Id)
		if err := app.Save(s); err != nil {
			t.Fatalf("Expected the actor to be assigned, got %v", err)
		}

		s.SetRecordRef(user2.Id)
		tests.TestValidationErrors(t, app.Validate(s), []string{"recordRef"})
	})
}

func TestAuthSessionHashedFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := stubOAuth2Client(t, app, "users", "hashed")

	s := newPendingAuthSession(t, app, client)
	s.SetHandle("handle_123")
	s.SetBinding("binding_123")
	s.SetUpstream("google", "upstream_123", "verifier_123")
	s.SetCode("code_123", types.NowDateTime().Add(time.Minute))
	s.SetRefreshToken("refresh_1")
	s.SetCodeChallenge(security.S256Challenge("pkce_verifier"), "S256")
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}

	// no plain values are stored
	raw, err := json.Marshal(s.Record.FieldsData())
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"handle_123", "binding_123", "upstream_123", "code_123", "refresh_1"} {
		if strings.Contains(string(raw), plain) {
			t.Fatalf("Expected %q to be stored hashed, got %s", plain, raw)
		}
	}

	// hidden from the public export
	export, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"handleHash", "bindingHash", "ssoSecretHash", "upstreamState", "upstreamCodeVerifier", "codeHash", "refreshTokenHash"} {
		if strings.Contains(string(export), `"`+field+`"`) {
			t.Fatalf("Expected %q to be hidden, got %s", field, export)
		}
	}

	checks := []struct {
		name   string
		result bool
		expect bool
	}{
		{"valid binding", s.ValidateBinding("binding_123"), true},
		{"invalid binding", s.ValidateBinding("binding_1234"), false},
		{"empty binding", s.ValidateBinding(""), false},
		{"sso secret of a non-root session", s.ValidateSSOSecret("sso_123"), false},
		{"valid upstream", s.ValidateUpstreamState("upstream_123"), true},
		{"invalid upstream", s.ValidateUpstreamState("x"), false},
		{"valid refresh", s.ValidateRefreshToken("refresh_1"), true},
		{"invalid refresh", s.ValidateRefreshToken("refresh_2"), false},
		{"valid pkce", s.ValidateCodeVerifier("pkce_verifier"), true},
		{"invalid pkce", s.ValidateCodeVerifier("pkce_verifier2"), false},
		{"empty pkce", s.ValidateCodeVerifier(""), false},
		{"is not root", s.IsRoot(), false},
	}
	for _, c := range checks {
		if c.result != c.expect {
			t.Errorf("[%s] Expected %v, got %v", c.name, c.expect, c.result)
		}
	}

	if s.UpstreamProvider() != "google" || s.UpstreamCodeVerifier() != "verifier_123" {
		t.Fatalf("Unexpected upstream data %q, %q", s.UpstreamProvider(), s.UpstreamCodeVerifier())
	}

	// lookups
	if found, err := app.FindAuthSessionByHandle("handle_123"); err != nil || found.Id != s.Id {
		t.Fatalf("Expected to find the session by handle, got %v", err)
	}
	if _, err := app.FindAuthSessionByHandle("handle_1234"); err == nil {
		t.Fatal("Expected not found for invalid handle")
	}
	if _, err := app.FindAuthSessionByHandle(""); err == nil {
		t.Fatal("Expected not found for empty handle")
	}
	if found, err := app.FindAuthSessionByCode("code_123"); err != nil || found.Id != s.Id {
		t.Fatalf("Expected to find the session by code, got %v", err)
	}
	if found, err := app.FindAuthSessionByRefreshToken("refresh_1"); err != nil || found.Id != s.Id {
		t.Fatalf("Expected to find the session by refresh token, got %v", err)
	}

	// rotation
	s.RotateRefreshToken("refresh_2")
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthSessionByRefreshToken("refresh_1"); err == nil {
		t.Fatal("Expected the rotated refresh token to be no longer current")
	}
	if found, err := app.FindAuthSessionByPrevRefreshToken("refresh_1"); err != nil || found.Id != s.Id {
		t.Fatalf("Expected to find the session by the previous refresh token, got %v", err)
	}
	if found, err := app.FindAuthSessionByRefreshToken("refresh_2"); err != nil || found.Id != s.Id {
		t.Fatalf("Expected to find the session by the new refresh token, got %v", err)
	}

	// pending upstream result (clears the single use state and verifier but keeps the provider)
	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.SetUpstreamResult(user.Id)
	if s.UpstreamRecordRef() != user.Id || s.UpstreamProvider() != "google" || s.UpstreamCodeVerifier() != "" || s.ValidateUpstreamState("upstream_123") {
		t.Fatal("Unexpected pending upstream result state")
	}
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}
	if export, _ := json.Marshal(s); strings.Contains(string(export), `"upstreamRecordRef"`) || strings.Contains(string(export), `"upstreamProvider"`) {
		t.Fatalf("Expected hidden upstream fields, got %s", export)
	}

	// clear upstream
	s.SetUpstream("", "", "")
	if s.UpstreamRecordRef() != "" {
		t.Fatal("Expected the pending upstream result to be cleared")
	}
	if s.ValidateUpstreamState("upstream_123") || s.UpstreamProvider() != "" {
		t.Fatal("Expected the upstream data to be cleared")
	}
}

func TestAuthSessionAuthMethods(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	s := core.NewAuthSession(app)

	if len(s.AuthMethods()) != 0 || !s.AuthTime().IsZero() {
		t.Fatal("Expected no auth methods")
	}

	old := types.NowDateTime().Add(-time.Hour)
	s.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodOTP, Time: old}})

	s.AddAuthMethod(core.AuthSessionMethodPassword, "")
	s.AddAuthMethod(core.AuthSessionMethodOAuth2, "google")
	s.AddAuthMethod(core.AuthSessionMethodOAuth2, "github")

	methods := s.AuthMethods()
	if len(methods) != 4 || methods[2].Provider != "google" || methods[3].Provider != "github" {
		t.Fatalf("Unexpected amr %#v", methods)
	}

	if time.Since(s.AuthTime().Time()) > 5*time.Second {
		t.Fatalf("Expected the auth time to be updated, got %v", s.AuthTime())
	}

	if !s.HasAuthMethod(core.AuthSessionMethodOTP) || s.HasAuthMethod("unknown") {
		t.Fatal("Unexpected HasAuthMethod result")
	}

	// the oauth2 providers count as a single method and the old factors are excluded
	distinct := s.DistinctAuthMethods(time.Now().Add(-10 * time.Minute))
	if len(distinct) != 2 || !slices.Contains(distinct, core.AuthSessionMethodPassword) || !slices.Contains(distinct, core.AuthSessionMethodOAuth2) {
		t.Fatalf("Unexpected distinct methods %v", distinct)
	}

	all := s.DistinctAuthMethods(time.Now().Add(-2 * time.Hour))
	if len(all) != 3 {
		t.Fatalf("Expected 3 distinct methods, got %v", all)
	}
}

func TestCreateAuthSession(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, err := app.FindRecordById("demo1", "84nmscqy84lsi1t")
	if err != nil {
		t.Fatal(err)
	}

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	usersClient := stubOAuth2Client(t, app, "users", "users_client")
	clientsClient := stubOAuth2Client(t, app, "clients", "clients_client")
	disabledClient := stubOAuth2Client(t, app, "users", "disabled_client")
	disabledClient.SetDisabled(true)
	if err := app.Save(disabledClient); err != nil {
		t.Fatal(err)
	}

	staff, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	staffSession, err := tests.CreateAuthSession(app, staff)
	if err != nil {
		t.Fatal(err)
	}
	endedStaffSession, err := tests.CreateAuthSession(app, staff)
	if err != nil {
		t.Fatal(err)
	}
	_ = endedStaffSession.End()
	if err := app.Save(endedStaffSession); err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		record      *core.Record
		client      *core.OAuth2Client
		opts        core.AuthSessionOptions
		expectError bool
	}{
		{"non-auth record", demo1, usersClient, core.AuthSessionOptions{}, true},
		{"nil client", user, nil, core.AuthSessionOptions{}, true},
		{"disabled client", user, disabledClient, core.AuthSessionOptions{}, true},
		{"client of another collection", user, clientsClient, core.AuthSessionOptions{}, true},
		{"scope not allowed for the client", user, usersClient, core.AuthSessionOptions{Scopes: []string{"profile"}}, true},
		{"unknown scope", user, usersClient, core.AuthSessionOptions{Scopes: []string{"unknown"}}, true},
		{"default client scopes", user, usersClient, core.AuthSessionOptions{}, false},
		{"impersonator without impersonator session", user, usersClient, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id}, true},
		{"unknown impersonator", user, usersClient, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: "abc", ImpersonatorSession: staffSession.Id}, true},
		{"ended impersonator session", user, usersClient, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: endedStaffSession.Id}, true},
		{"root impersonator session", user, usersClient, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: staffSession.Parent()}, true},
		{"explicit scopes and impersonator", user, usersClient, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: staffSession.Id}, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			session, err := app.CreateAuthSession(s.record, s.client, s.opts)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				return
			}

			if session.IsNew() || !session.IsActive() || session.RecordRef() != user.Id || session.Client() != usersClient.Id {
				t.Fatalf("Unexpected session %v", session)
			}

			expectedScopes := s.opts.Scopes
			if len(expectedScopes) == 0 {
				expectedScopes = usersClient.Scopes()
			}
			if !slices.Equal(session.Scopes(), expectedScopes) {
				t.Fatalf("Expected scopes %v, got %v", expectedScopes, session.Scopes())
			}

			if session.Impersonator() != s.opts.Impersonator || session.ImpersonatorSession() != s.opts.ImpersonatorSession {
				t.Fatalf("Expected impersonator %q/%q, got %q/%q", s.opts.Impersonator, s.opts.ImpersonatorSession, session.Impersonator(), session.ImpersonatorSession())
			}

			// default to the collection auth token duration
			expectedExp := time.Now().Add(user.Collection().AuthToken.DurationTime())
			if diff := session.ExpiresAt().Time().Sub(expectedExp); diff > 5*time.Second || diff < -5*time.Second {
				t.Fatalf("Expected expiresAt ~%v, got %v", expectedExp, session.ExpiresAt())
			}

			// the actor and client are attached
			if _, err := session.NewAccessToken(); err != nil {
				t.Fatalf("Expected the access token to be generated, got %v", err)
			}
		})
	}
}

func TestAuthSessionNewAccessToken(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user2, err := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := stubOAuth2Client(t, app, "users", "token_client")
	client2 := stubOAuth2Client(t, app, "users", "token_client2")

	t.Run("unsaved session", func(t *testing.T) {
		s := core.NewAuthSession(app)
		if _, err := s.NewAccessToken(); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("not attached actor", func(t *testing.T) {
		s := stubAuthSession(t, app, client, user, []string{"openid"})
		fresh, err := app.FindAuthSessionById(s.Id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.NewAccessToken(); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("attach mismatch", func(t *testing.T) {
		s := stubAuthSession(t, app, client, user, []string{"openid"})
		if err := s.AttachActor(user2, client); err == nil {
			t.Fatal("Expected record mismatch error")
		}
		if err := s.AttachActor(user, client2); err == nil {
			t.Fatal("Expected client mismatch error")
		}
		if err := s.AttachActor(nil, client); err == nil {
			t.Fatal("Expected nil record error")
		}
	})

	t.Run("not active session", func(t *testing.T) {
		s := stubAuthSession(t, app, client, user, []string{"openid"})
		if err := s.End(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.NewAccessToken(); err == nil {
			t.Fatal("Expected error for ended session")
		}
	})

	t.Run("valid", func(t *testing.T) {
		s := stubAuthSession(t, app, client, user, []string{"openid", "email"})

		token, err := s.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		// signed with tokenKey + AuthToken.Secret
		claims, err := security.ParseJWT(token, user.TokenKey()+user.Collection().AuthToken.Secret)
		if err != nil {
			t.Fatal(err)
		}

		expectedClaims := map[string]any{
			core.TokenClaimType:            core.TokenTypeAuth,
			core.TokenClaimId:              user.Id,
			core.TokenClaimCollectionId:    user.Collection().Id,
			core.TokenClaimOAuth2ClientId:  "token_client",
			core.TokenClaimOAuth2Scope:     "openid email",
			core.TokenClaimOAuth2SessionId: s.Id,
		}
		for k, v := range expectedClaims {
			if claims[k] != v {
				t.Errorf("Expected claim %q with value %#v, got %#v", k, v, claims[k])
			}
		}

		for _, k := range []string{core.TokenClaimOAuth2Actor, "refreshable"} {
			if _, ok := claims[k]; ok {
				t.Errorf("Expected no %q claim", k)
			}
		}

		// duration = AuthToken.Duration
		exp := cast.ToInt64(claims["exp"])
		expectedExp := time.Now().Add(user.Collection().AuthToken.DurationTime()).Unix()
		if exp < expectedExp-5 || exp > expectedExp+5 {
			t.Fatalf("Expected exp ~%d, got %d", expectedExp, exp)
		}

		record, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth)
		if err != nil || record.Id != user.Id {
			t.Fatalf("Expected the token to be valid, got %v", err)
		}
	})

	t.Run("impersonation act claim", func(t *testing.T) {
		s := stubAuthSession(t, app, client, user, []string{"openid"}, func(s *core.AuthSession) {
			s.SetImpersonator("staff_id")
		})
		if err := s.AttachActor(user, client); err != nil {
			t.Fatal(err)
		}

		token, err := s.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		claims, _ := security.ParseUnverifiedJWT(token)
		act, _ := claims[core.TokenClaimOAuth2Actor].(map[string]any)
		if act["sub"] != "staff_id" {
			t.Fatalf("Expected act claim with sub staff_id, got %v", claims[core.TokenClaimOAuth2Actor])
		}
	})
}

func TestFindAuthRecordByTokenWithSessions(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user1, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	user2, err := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := stubOAuth2Client(t, app, "users", "test")
	otherClient := stubOAuth2Client(t, app, "users", "other")

	newToken := func(extraClaims jwt.MapClaims) string {
		claims := jwt.MapClaims{
			core.TokenClaimType:         core.TokenTypeAuth,
			core.TokenClaimId:           user1.Id,
			core.TokenClaimCollectionId: user1.Collection().Id,
		}
		for k, v := range extraClaims {
			claims[k] = v
		}

		token, err := security.NewJWT(claims, user1.TokenKey()+user1.Collection().AuthToken.Secret, 1*time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		return token
	}

	sessionToken := func(s *core.AuthSession) string {
		return newToken(jwt.MapClaims{
			core.TokenClaimOAuth2SessionId: s.Id,
			core.TokenClaimOAuth2ClientId:  "test",
			core.TokenClaimOAuth2Scope:     "openid",
		})
	}

	active := stubAuthSession(t, app, client, user1, []string{"openid"})
	expired := stubAuthSession(t, app, client, user1, []string{"openid"}, func(s *core.AuthSession) {
		s.SetExpiresAt(types.NowDateTime().Add(-time.Second))
	})
	ended := stubAuthSession(t, app, client, user1, []string{"openid"}, func(s *core.AuthSession) {
		_ = s.End()
	})
	user2Session := stubAuthSession(t, app, client, user2, []string{"openid"})

	// root SSO session with children
	root := stubSSORoot(t, app, user1)
	child := stubAuthSession(t, app, client, user1, []string{"openid"}, func(s *core.AuthSession) {
		s.SetParent(root.Id)
	})
	offlineChild := stubAuthSession(t, app, client, user1, []string{"openid", core.OAuth2ScopeOfflineAccess}, func(s *core.AuthSession) {
		s.SetParent(root.Id)
	})
	orphanChild := stubAuthSession(t, app, client, user1, []string{"openid"}, func(s *core.AuthSession) {
		s.SetParent("missing_root")
	})

	activeToken, err := active.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		token       string
		expectError bool
	}{
		{"sid-less auth token (valid signature)", newToken(nil), true},
		{"session token from NewAccessToken", activeToken, false},
		{"active session", sessionToken(active), false},
		{"expired session", sessionToken(expired), true},
		{"ended session", sessionToken(ended), true},
		{"session of another record", sessionToken(user2Session), true},
		{"missing session", newToken(jwt.MapClaims{core.TokenClaimOAuth2SessionId: "missing", core.TokenClaimOAuth2ClientId: "test"}), true},
		{"empty sid", newToken(jwt.MapClaims{core.TokenClaimOAuth2SessionId: ""}), true},
		{"non-string sid", newToken(jwt.MapClaims{core.TokenClaimOAuth2SessionId: 123}), true},
		{"sid without cid", newToken(jwt.MapClaims{core.TokenClaimOAuth2SessionId: active.Id}), true},
		{"sid with different cid", newToken(jwt.MapClaims{core.TokenClaimOAuth2SessionId: active.Id, core.TokenClaimOAuth2ClientId: otherClient.ClientId()}), true},
		{"cid but without sid", newToken(jwt.MapClaims{core.TokenClaimOAuth2ClientId: "test"}), true},
		{"scope but without sid", newToken(jwt.MapClaims{core.TokenClaimOAuth2Scope: "openid"}), true},
		{"act but without sid", newToken(jwt.MapClaims{core.TokenClaimOAuth2Actor: map[string]any{"sub": "x"}}), true},
		{"child of active root", sessionToken(child), false},
		{"offline child of active root", sessionToken(offlineChild), false},
		{"child of missing root", sessionToken(orphanChild), true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			record, err := app.FindAuthRecordByToken(s.token, core.TokenTypeAuth)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if !hasErr && record.Id != user1.Id {
				t.Fatalf("Expected record %q, got %q", user1.Id, record.Id)
			}
		})
	}

	// the root expiration (without explicit ending) also invalidates the non-offline children
	// ---
	root.SetExpiresAt(types.NowDateTime().Add(-time.Second))
	if err := app.SaveNoValidate(root); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(sessionToken(child)); err == nil {
		t.Fatal("Expected the child token to be rejected after the root expiration")
	}
	if _, err := app.FindAuthRecordByToken(sessionToken(offlineChild)); err != nil {
		t.Fatalf("Expected the offline child token to remain valid, got %v", err)
	}

	// disabled and deleted clients
	// ---
	client2 := stubOAuth2Client(t, app, "users", "test2")
	client2Session := stubAuthSession(t, app, client2, user1, []string{"openid"})
	client2Token, err := client2Session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(client2Token); err != nil {
		t.Fatalf("Expected the access token of the enabled client to be valid, got %v", err)
	}

	// simulate a disabled client without the sessions ending hook
	if _, err := app.NonconcurrentDB().Update(core.CollectionNameOAuth2Clients, dbx.Params{"disabled": true}, dbx.HashExp{"id": client2.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(client2Token); err == nil {
		t.Fatal("Expected the access token to be rejected for disabled client")
	}

	// simulate a missing client without the relation cascade
	if _, err := app.NonconcurrentDB().Delete(core.CollectionNameOAuth2Clients, dbx.HashExp{"id": client2.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(client2Token); err == nil {
		t.Fatal("Expected the access token to be rejected for missing client")
	}
}

func TestAuthSessionCascades(t *testing.T) {
	t.Parallel()

	reload := func(t testing.TB, app core.App, id string) *core.AuthSession {
		t.Helper()
		s, err := app.FindAuthSessionById(id)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("root ending ends the non-offline children", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		client := stubOAuth2Client(t, app, "users", "c1")

		root := stubSSORoot(t, app, user)
		child := stubAuthSession(t, app, client, user, []string{"openid"}, func(s *core.AuthSession) { s.SetParent(root.Id) })
		offline := stubAuthSession(t, app, client, user, []string{"openid", core.OAuth2ScopeOfflineAccess}, func(s *core.AuthSession) { s.SetParent(root.Id) })
		pendingChild := newPendingAuthSession(t, app, client)
		pendingChild.SetParent(root.Id)
		if err := app.Save(pendingChild); err != nil {
			t.Fatal(err)
		}
		unrelated := stubAuthSession(t, app, client, user, []string{"openid"})

		if err := root.End(); err != nil {
			t.Fatal(err)
		}
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		if s := reload(t, app, child.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the child to be ended, got %q", s.Status())
		}
		if s := reload(t, app, pendingChild.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the pending child to be ended, got %q", s.Status())
		}
		if s := reload(t, app, offline.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the offline_access child to survive, got %q", s.Status())
		}
		if s := reload(t, app, unrelated.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the unrelated session to remain active, got %q", s.Status())
		}
	})

	t.Run("tokenKey (password) change ends all record sessions", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		user2, _ := app.FindAuthRecordByEmail("users", "test2@example.com")
		client := stubOAuth2Client(t, app, "users", "c1")

		s1 := stubAuthSession(t, app, client, user, []string{"openid", core.OAuth2ScopeOfflineAccess})
		s2 := stubAuthSession(t, app, client, user, []string{"openid"})
		other := stubAuthSession(t, app, client, user2, []string{"openid"})

		user.SetPassword("new_password_123")
		if err := app.Save(user); err != nil {
			t.Fatal(err)
		}

		for _, id := range []string{s1.Id, s2.Id} {
			if s := reload(t, app, id); s.Status() != core.AuthSessionStatusEnded {
				t.Fatalf("Expected %q to be ended, got %q", id, s.Status())
			}
		}
		if s := reload(t, app, other.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the other record session to remain active, got %q", s.Status())
		}
	})

	t.Run("record delete deletes all record sessions and consents", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		client := stubOAuth2Client(t, app, "users", "c1")

		s1 := stubAuthSession(t, app, client, user, []string{"openid"})
		if _, err := app.SaveOAuth2Consent(user, client, []string{"openid"}); err != nil {
			t.Fatal(err)
		}

		if err := app.Delete(user); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAuthSessionById(s1.Id); err == nil {
			t.Fatal("Expected the session to be deleted")
		}
		if total, _ := app.CountRecords(core.CollectionNameOAuth2Consents); total != 0 {
			t.Fatalf("Expected the consents to be deleted, got %d", total)
		}
	})

	t.Run("client disable ends all client sessions", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		client := stubOAuth2Client(t, app, "users", "c1")
		client2 := stubOAuth2Client(t, app, "users", "c2")

		s1 := stubAuthSession(t, app, client, user, []string{"openid", core.OAuth2ScopeOfflineAccess})
		s2 := stubAuthSession(t, app, client2, user, []string{"openid"})

		client.SetDisabled(true)
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}

		if s := reload(t, app, s1.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the disabled client session to be ended, got %q", s.Status())
		}
		if s := reload(t, app, s2.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the other client session to remain active, got %q", s.Status())
		}

		// re-enabling doesn't revive the ended sessions
		client.SetDisabled(false)
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}
		if s := reload(t, app, s1.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the session to remain ended, got %q", s.Status())
		}
	})

	t.Run("client disable/delete never ends the root SSO sessions", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		client1 := stubOAuth2Client(t, app, "users", "c1")
		client2 := stubOAuth2Client(t, app, "users", "c2")

		root := stubSSORoot(t, app, user)
		child1 := stubAuthSession(t, app, client1, user, []string{"openid"}, func(s *core.AuthSession) { s.SetParent(root.Id) })
		child2 := stubAuthSession(t, app, client2, user, []string{"openid"}, func(s *core.AuthSession) { s.SetParent(root.Id) })

		client1.SetDisabled(true)
		if err := app.Save(client1); err != nil {
			t.Fatal(err)
		}

		if s := reload(t, app, child1.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the disabled client session to be ended, got %q", s.Status())
		}
		if s := reload(t, app, root.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the root to remain active, got %q", s.Status())
		}
		if s := reload(t, app, child2.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the other client child to remain active, got %q", s.Status())
		}

		if err := app.Delete(client2); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthSessionById(child2.Id); err == nil {
			t.Fatal("Expected the deleted client session to be deleted")
		}
		if s := reload(t, app, root.Id); s.Status() != core.AuthSessionStatusActive {
			t.Fatalf("Expected the root to remain active after the client delete, got %q", s.Status())
		}
	})

	t.Run("EndAllAuthSessionsByRecord skips terminal sessions", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		client := stubOAuth2Client(t, app, "users", "c1")

		failed := newPendingAuthSession(t, app, client)
		failed.SetRecordRef(user.Id)
		_ = failed.Fail()
		if err := app.Save(failed); err != nil {
			t.Fatal(err)
		}

		if err := app.EndAllAuthSessionsByRecord(user); err != nil {
			t.Fatal(err)
		}

		if s := reload(t, app, failed.Id); s.Status() != core.AuthSessionStatusFailed {
			t.Fatalf("Expected the failed session to remain failed, got %q", s.Status())
		}
	})
}

func TestDeleteExpiredAuthSessions(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	client := stubOAuth2Client(t, app, "users", "c1")

	active := stubAuthSession(t, app, client, user, []string{"openid"})
	pending := newPendingAuthSession(t, app, client)
	expired := stubAuthSession(t, app, client, user, []string{"openid"}, func(s *core.AuthSession) {
		s.SetExpiresAt(types.NowDateTime().Add(-time.Minute))
	})
	ended := stubAuthSession(t, app, client, user, []string{"openid"}, func(s *core.AuthSession) {
		_ = s.End()
	})
	failed := newPendingAuthSession(t, app, client)
	_ = failed.Fail()
	if err := app.Save(failed); err != nil {
		t.Fatal(err)
	}

	if err := app.DeleteExpiredAuthSessions(); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{active.Id, pending.Id} {
		if _, err := app.FindAuthSessionById(id); err != nil {
			t.Fatalf("Expected %q to remain, got %v", id, err)
		}
	}

	for _, id := range []string{expired.Id, ended.Id, failed.Id} {
		if _, err := app.FindAuthSessionById(id); err == nil {
			t.Fatalf("Expected %q to be deleted", id)
		}
	}

	all, err := app.FindAllAuthSessionsByRecord(user)
	if err != nil || len(all) != 1 || all[0].Id != active.Id {
		t.Fatalf("Expected only the active record session, got %v (%v)", all, err)
	}
}

func TestOAuth2Consents(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	clientsUser, _ := app.FindAuthRecordByEmail("clients", "test@example.com")
	client := stubOAuth2Client(t, app, "users", "c1")

	if _, err := app.FindOAuth2ConsentByRecordAndClient(user, client); err == nil {
		t.Fatal("Expected no consent")
	}

	c1, err := app.SaveOAuth2Consent(user, client, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	c2, err := app.SaveOAuth2Consent(user, client, []string{"email", "openid"})
	if err != nil {
		t.Fatal(err)
	}

	if c1.Id != c2.Id {
		t.Fatal("Expected the same (merged) consent")
	}

	if !slices.Equal(c2.Scopes(), []string{"openid", "email"}) {
		t.Fatalf("Expected merged scopes, got %v", c2.Scopes())
	}

	if !c2.Covers([]string{"email"}) || c2.Covers([]string{"email", "profile"}) {
		t.Fatal("Unexpected Covers result")
	}

	all, err := app.FindAllOAuth2ConsentsByRecord(user)
	if err != nil || len(all) != 1 {
		t.Fatalf("Expected 1 consent, got %v (%v)", all, err)
	}

	// the consent client must be registered for the record collection
	invalid := core.NewOAuth2Consent(app)
	invalid.SetCollectionRef(clientsUser.Collection().Id)
	invalid.SetRecordRef(clientsUser.Id)
	invalid.SetClient(client.Id)
	tests.TestValidationErrors(t, app.Validate(invalid), []string{"client"})

	// the remembered consent decision only (no token fields)
	for _, name := range []string{"refreshTokenHash", "prevRefreshTokenHash", "revoked", "expiresAt"} {
		if c2.Collection().Fields.GetByName(name) != nil {
			t.Fatalf("Expected no %q consent field", name)
		}
	}
}

func TestOTPSessionRef(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	otp := core.NewOTP(app)
	if otp.SessionRef() != "" {
		t.Fatal("Expected empty sessionRef")
	}

	otp.SetSessionRef("abc")
	if otp.SessionRef() != "abc" {
		t.Fatalf("Expected sessionRef abc, got %q", otp.SessionRef())
	}

	if otp.Collection().Fields.GetByName("sessionRef") == nil {
		t.Fatal("Expected _otps.sessionRef field")
	}
}

func TestAuthSessionPreservedCascades(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	kept, err := tests.CreateAuthSession(app, user)
	if err != nil {
		t.Fatal(err)
	}
	keptRoot := kept.Parent()

	other, err := tests.CreateAuthSession(app, user)
	if err != nil {
		t.Fatal(err)
	}

	// a sibling child of the kept session root
	client, err := app.FindOAuth2ClientById(kept.Client())
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Parent: keptRoot})
	if err != nil {
		t.Fatal(err)
	}

	// tokenKey change with the kept session preserved
	user.RefreshTokenKey()
	ctx := core.WithPreservedAuthSessions(context.Background(), kept.Id)
	if err := app.SaveWithContext(ctx, user); err != nil {
		t.Fatal(err)
	}

	status := func(id string) string {
		s, err := app.FindAuthSessionById(id)
		if err != nil {
			t.Fatal(err)
		}
		return s.Status()
	}

	if s := status(kept.Id); s != core.AuthSessionStatusActive {
		t.Fatalf("Expected the preserved session to be active, got %q", s)
	}
	for _, id := range []string{other.Id, other.Parent(), keptRoot, sibling.Id} {
		if s := status(id); s != core.AuthSessionStatusEnded {
			t.Fatalf("Expected session %q to be ended, got %q", id, s)
		}
	}

	// the preserved ids accumulate
	ctx2 := core.WithPreservedAuthSessions(ctx, "b")
	user.RefreshTokenKey()
	if err := app.SaveWithContext(ctx2, user); err != nil {
		t.Fatal(err)
	}
	if s := status(kept.Id); s != core.AuthSessionStatusActive {
		t.Fatalf("Expected the preserved session to remain active, got %q", s)
	}

	// without context the regular cascade applies
	user.RefreshTokenKey()
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}
	if s := status(kept.Id); s != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the session to be ended without preservation, got %q", s)
	}
}

func TestIsAuthSessionRootAliveAndEndAuthSession(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	session, err := tests.CreateAuthSession(app, user, "openid")
	if err != nil {
		t.Fatal(err)
	}

	if !app.IsAuthSessionRootAlive(session) {
		t.Fatal("Expected the root session to be alive")
	}

	// root-less session
	if !app.IsAuthSessionRootAlive(core.NewAuthSession(app)) {
		t.Fatal("Expected a root-less session to be always alive")
	}

	root, err := app.FindAuthSessionById(session.Parent())
	if err != nil {
		t.Fatal(err)
	}

	if err := app.EndAuthSession(root, "test"); err != nil {
		t.Fatal(err)
	}

	if app.IsAuthSessionRootAlive(session) {
		t.Fatal("Expected the root session to be ended")
	}

	fresh, err := app.FindAuthSessionById(session.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.IsTerminal() {
		t.Fatalf("Expected the child session to be ended together with its root, got %q", fresh.Status())
	}

	// already ended -> no-op
	if err := app.EndAuthSession(fresh, "test"); err != nil {
		t.Fatalf("Expected no error for an already ended session, got %v", err)
	}
}

func TestAuthSessionPreValidate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	ctx := context.Background()

	t.Run("nil record", func(t *testing.T) {
		s := &core.AuthSession{}

		if err := s.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for nil record")
		}
	})

	t.Run("wrong collection", func(t *testing.T) {
		s := &core.AuthSession{}
		s.SetProxyRecord(core.NewRecord(core.NewBaseCollection("not_auth_sessions")))

		if err := s.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for non auth session collection")
		}
	})

	t.Run("valid", func(t *testing.T) {
		s := core.NewAuthSession(app)

		if err := s.PreValidate(ctx, app); err != nil {
			t.Fatalf("Expected valid proxy, got %v", err)
		}
	})
}

func TestAuthSessionFieldAccessors(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	s := core.NewAuthSession(app)

	s.SetParent("root_session_id")
	if s.Parent() != "root_session_id" {
		t.Fatalf("Expected parent %q, got %q", "root_session_id", s.Parent())
	}

	s.SetRedirectURI("https://example.com/callback")
	if s.RedirectURI() != "https://example.com/callback" {
		t.Fatalf("Unexpected redirect URI %q", s.RedirectURI())
	}

	s.SetResponseMode("form_post")
	if s.ResponseMode() != "form_post" {
		t.Fatalf("Unexpected response mode %q", s.ResponseMode())
	}

	s.SetState("client_state")
	if s.State() != "client_state" {
		t.Fatalf("Unexpected state %q", s.State())
	}

	s.SetNonce("client_nonce")
	if s.Nonce() != "client_nonce" {
		t.Fatalf("Unexpected nonce %q", s.Nonce())
	}

	s.SetPrompt("login consent")
	if s.Prompt() != "login consent" {
		t.Fatalf("Unexpected prompt %q", s.Prompt())
	}

	s.SetLoginHint("user@example.com")
	if s.LoginHint() != "user@example.com" {
		t.Fatalf("Unexpected login hint %q", s.LoginHint())
	}

	s.SetUILocales("en-US fr")
	if s.UILocales() != "en-US fr" {
		t.Fatalf("Unexpected ui locales %q", s.UILocales())
	}

	s.SetMFARequired(true)
	if !s.MFARequired() {
		t.Fatal("Expected MFARequired to be true")
	}
	s.SetMFARequired(false)
	if s.MFARequired() {
		t.Fatal("Expected MFARequired to be false")
	}

	s.SetMaxAge(3600)
	if s.MaxAge() != 3600 {
		t.Fatalf("Expected maxAge 3600, got %d", s.MaxAge())
	}
	// negative values are normalized to -1 (unset)
	s.SetMaxAge(-10)
	if s.MaxAge() != -1 {
		t.Fatalf("Expected normalized maxAge -1, got %d", s.MaxAge())
	}

	s.SetIP("203.0.113.10")
	if s.IP() != "203.0.113.10" {
		t.Fatalf("Unexpected IP %q", s.IP())
	}

	s.SetUserAgent("Go-http-client/1.1")
	if s.UserAgent() != "Go-http-client/1.1" {
		t.Fatalf("Unexpected user agent %q", s.UserAgent())
	}
	// user agents are truncated to 255 chars
	s.SetUserAgent(strings.Repeat("a", 300))
	if ua := s.UserAgent(); len(ua) != 255 {
		t.Fatalf("Expected the user agent to be truncated to 255 chars, got %d", len(ua))
	}

	lastUsed := types.NowDateTime().Add(-time.Minute)
	s.SetLastUsedAt(lastUsed)
	if !s.LastUsedAt().Equal(lastUsed) {
		t.Fatalf("Unexpected lastUsedAt %v", s.LastUsedAt())
	}

	created := types.NowDateTime()
	client := stubOAuth2Client(t, app, "users", "accessors")
	saved := core.NewAuthSession(app)
	saved.SetCollectionRef(client.CollectionRef())
	saved.SetExpiresAt(types.NowDateTime().Add(time.Hour))
	saved.SetClient(client.Id)
	if err := app.Save(saved); err != nil {
		t.Fatal(err)
	}
	if saved.Created().IsZero() || saved.Updated().IsZero() {
		t.Fatalf("Expected non-zero created/updated, got %v / %v", saved.Created(), saved.Updated())
	}
	if saved.Created().Time().Before(created.Time().Add(-time.Minute)) {
		t.Fatalf("Unexpected created date %v", saved.Created())
	}

	// no cached actor before AttachActor
	if saved.Actor() != nil {
		t.Fatal("Expected nil actor for a session that was not attached")
	}
}

func TestAuthSessionCodeAndRefreshState(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := stubOAuth2Client(t, app, "users", "code_state")
	s := newPendingAuthSession(t, app, client)

	if s.CodeConsumed() {
		t.Fatal("Expected a fresh code to be not consumed")
	}
	s.SetCodeConsumed(true)
	if !s.CodeConsumed() {
		t.Fatal("Expected the code to be consumed")
	}
	s.SetCodeConsumed(false)
	if s.CodeConsumed() {
		t.Fatal("Expected the code to not be consumed")
	}

	// not expired code
	if !s.CodeExpiresAt().IsZero() {
		t.Fatalf("Expected empty code expiration, got %v", s.CodeExpiresAt())
	}
	// an empty expiration is treated as expired
	if !s.HasCodeExpired() {
		t.Fatal("Expected a missing code expiration to be treated as expired")
	}

	s.SetCode("code_123", types.NowDateTime().Add(time.Minute))
	if s.HasCodeExpired() {
		t.Fatal("Expected a future code to be not expired")
	}
	s.SetCode("code_123", types.NowDateTime().Add(-time.Minute))
	if !s.HasCodeExpired() {
		t.Fatal("Expected a past code to be expired")
	}

	if s.HasRefreshToken() {
		t.Fatal("Expected no refresh token")
	}
	s.SetRefreshToken("refresh_123")
	if !s.HasRefreshToken() {
		t.Fatal("Expected a refresh token")
	}

	if !s.RefreshExpiresAt().IsZero() {
		t.Fatalf("Expected empty refresh expiration, got %v", s.RefreshExpiresAt())
	}
	if !s.HasRefreshExpired() {
		t.Fatal("Expected a missing refresh expiration to be treated as expired")
	}

	s.SetRefreshExpiresAt(types.NowDateTime().Add(time.Minute))
	if s.HasRefreshExpired() {
		t.Fatal("Expected a future refresh expiration to be not expired")
	}
	s.SetRefreshExpiresAt(types.NowDateTime().Add(-time.Minute))
	if !s.HasRefreshExpired() {
		t.Fatal("Expected a past refresh expiration to be expired")
	}
}

func TestAuthSessionAttachActorAndTokenErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrNotAuthRecord", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		demo, err := app.FindAllRecords("demo1")
		if err != nil || len(demo) == 0 {
			t.Fatalf("Expected demo1 records, got %v (%v)", len(demo), err)
		}
		demoRecord := demo[0]

		// stubbed non-auth client/session (bypassing the validators)
		client := core.NewOAuth2Client(app)
		client.SetName("non-auth client")
		client.SetClientId("non_auth_client")
		client.SetType(core.OAuth2ClientTypePublic)
		client.SetCollectionRef(demoRecord.Collection().Id)
		if err := app.SaveNoValidate(client); err != nil {
			t.Fatal(err)
		}

		s := core.NewAuthSession(app)
		s.Set("status", core.AuthSessionStatusActive)
		s.SetCollectionRef(demoRecord.Collection().Id)
		s.SetClient(client.Id)
		s.SetRecordRef(demoRecord.Id)
		s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
		if err := app.SaveNoValidate(s); err != nil {
			t.Fatal(err)
		}

		if err := s.AttachActor(demoRecord, client); err != nil {
			t.Fatal(err)
		}
		if s.Actor() != demoRecord {
			t.Fatal("Expected the attached actor")
		}

		if _, err := s.NewAccessToken(); !errors.Is(err, core.ErrNotAuthRecord) {
			t.Fatalf("Expected ErrNotAuthRecord, got %v", err)
		}
	})

	t.Run("ErrMissingSigningKey", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		collection := core.NewAuthCollection("no_key_auth")
		collection.AuthToken.Secret = ""
		if err := app.SaveNoValidate(collection); err != nil {
			t.Fatal(err)
		}

		record := core.NewRecord(collection)
		record.SetEmail("nokey@example.com")
		record.SetPassword("1234567890")
		if err := app.SaveNoValidate(record); err != nil {
			t.Fatal(err)
		}

		// keep the token key empty (the field autogeneration applies only on create)
		record.Set("tokenKey", "")
		if err := app.SaveNoValidate(record); err != nil {
			t.Fatal(err)
		}

		freshRecord, err := app.FindRecordById(collection, record.Id)
		if err != nil {
			t.Fatal(err)
		}
		if freshRecord.TokenKey() != "" {
			t.Fatalf("Expected an empty token key, got %q", freshRecord.TokenKey())
		}

		client := stubOAuth2Client(t, app, collection.Name, "nokeyclient")

		s := core.NewAuthSession(app)
		s.Set("status", core.AuthSessionStatusActive)
		s.SetCollectionRef(collection.Id)
		s.SetClient(client.Id)
		s.SetRecordRef(freshRecord.Id)
		s.SetExpiresAt(types.NowDateTime().Add(time.Hour))
		if err := app.Save(s); err != nil {
			t.Fatal(err)
		}

		if err := s.AttachActor(freshRecord, client); err != nil {
			t.Fatal(err)
		}

		if _, err := s.NewAccessToken(); !errors.Is(err, core.ErrMissingSigningKey) {
			t.Fatalf("Expected ErrMissingSigningKey, got %v", err)
		}
	})
}

// TestAuthSessionStaleSaveCannotResurrect checks that the status transitions are validated
// against the persisted session state (lost update of a stale session model).
func TestAuthSessionStaleSaveCannotResurrect(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := stubOAuth2Client(t, app, "users", "stale_client")

	session, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}

	// two copies loaded at the same time (e.g. an in-flight request and a logout)
	stale, err := app.FindAuthSessionById(session.Id)
	if err != nil {
		t.Fatal(err)
	}
	current, err := app.FindAuthSessionById(session.Id)
	if err != nil {
		t.Fatal(err)
	}

	if err := current.End(); err != nil {
		t.Fatal(err)
	}
	if err := app.Save(current); err != nil {
		t.Fatal(err)
	}

	// the stale (still "active") copy only touches a non-status field
	stale.SetLastUsedAt(types.NowDateTime())
	err = app.Save(stale)
	if !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
		t.Fatalf("Expected ErrInvalidAuthSessionTransition, got %v", err)
	}

	fresh, err := app.FindAuthSessionById(session.Id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the session to stay ended, got %q", fresh.Status())
	}

	// the same terminal status could still be saved (e.g. a stale ended copy)
	ended, _ := app.FindAuthSessionById(session.Id)
	ended.SetLastUsedAt(types.NowDateTime())
	if err := app.Save(ended); err != nil {
		t.Fatalf("Expected the ended session to be saved, got %v", err)
	}

	// SaveNoValidate (e.g. the scopes rename rewrite) is also checked
	stale.SetUserAgent("test")
	if err := app.SaveNoValidate(stale); !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
		t.Fatalf("Expected ErrInvalidAuthSessionTransition on SaveNoValidate, got %v", err)
	}
}

// TestAuthSessionStaleTransitionRegression checks that a stale earlier status can't overwrite a later one.
func TestAuthSessionStaleTransitionRegression(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := stubOAuth2Client(t, app, "users", "stale_client")

	s := newPendingAuthSession(t, app, client)

	stale, _ := app.FindAuthSessionById(s.Id)

	if err := s.Fail(); err != nil {
		t.Fatal(err)
	}
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}

	// pending -> authenticated is valid for the stale copy but not for the persisted "failed" status
	if err := stale.MarkAuthenticated(); err != nil {
		t.Fatal(err)
	}
	if err := app.Save(stale); !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
		t.Fatalf("Expected ErrInvalidAuthSessionTransition, got %v", err)
	}
}
