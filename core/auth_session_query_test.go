package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestApplicationInstallationTokenSessionCheck(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	_, installed := installTestApplication(t, app, "token-app", core.Permissions{})

	now := types.NowDateTime()

	newToken := func(modify func(s *core.AuthSession)) string {
		s := core.NewAuthSession(app)
		s.Set("status", core.AuthSessionStatusActive)
		s.SetCollectionRef(installed.Installation.Collection().Id)
		s.SetClient(installed.Client.Id)
		s.SetRecordRef(installed.Installation.Id)
		s.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodClientCredentials, Time: now}})
		s.SetExpiresAt(now.Add(core.AuthSessionFlowDuration))
		if modify != nil {
			modify(s)
		}
		if err := app.Save(s); err != nil {
			t.Fatal(err)
		}

		record, _ := app.FindRecordById(core.CollectionNameApplicationInstallations, installed.Installation.Id)
		client, _ := app.FindOAuth2ClientById(installed.Client.Id)
		s.SetProxyRecord(s.Record)
		if err := s.AttachActor(record, client); err != nil {
			t.Fatal(err)
		}
		token, err := s.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	valid := newToken(nil)
	if _, err := app.FindAuthRecordByToken(valid, core.TokenTypeAuth); err != nil {
		t.Fatalf("Expected a valid client_credentials token, got %v", err)
	}

	// a root-less session with a different method of the installation can't be persisted
	// (see TestApplicationModelInvariants) and a client_credentials session with a parent
	// is rejected on validation; disabling the client (raw update) rejects the tokens
	if _, err := app.DB().NewQuery("UPDATE {{_oauth2Clients}} SET [[disabled]] = TRUE WHERE id = {:id}").
		Bind(map[string]any{"id": installed.Client.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(valid, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the disabled managed client token to be rejected")
	}

	if _, err := app.DB().NewQuery("UPDATE {{_oauth2Clients}} SET [[disabled]] = FALSE, [[grantTypes]] = '[\"authorization_code\"]' WHERE id = {:id}").
		Bind(map[string]any{"id": installed.Client.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(valid, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the token of a client without the client_credentials grant to be rejected")
	}

	// expired client_credentials sessions are purged by the cleanup
	if _, err := app.DB().NewQuery("UPDATE {{_authSessions}} SET [[expiresAt]] = '2000-01-01 00:00:00.000Z' WHERE [[recordRef]] = {:id}").
		Bind(map[string]any{"id": installed.Installation.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if err := app.DeleteExpiredAuthSessions(); err != nil {
		t.Fatal(err)
	}
	if sessions, _ := app.FindAllAuthSessionsByRecord(installed.Installation.Record); len(sessions) != 0 {
		t.Fatalf("Expected the expired sessions to be purged, got %d", len(sessions))
	}
}
