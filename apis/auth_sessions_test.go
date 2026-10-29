package apis_test

import (
	"net/http"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestAuthSessionEndStaff(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !app.IsOwnerRecord(owner) {
		t.Fatal("Expected test@example.com to be an Owner")
	}

	extCreateStaff(t, app, "sessions_writer@example.com", core.Permissions{
		System: map[string]string{core.PermissionResourceSessions: core.PermissionLevelWrite},
	})
	extCreateStaff(t, app, "sessions_reader@example.com", core.Permissions{
		System: map[string]string{core.PermissionResourceSessions: core.PermissionLevelRead},
	})

	_, writerToken := extStaffSession(t, app, "sessions_writer@example.com")
	_, readerToken := extStaffSession(t, app, "sessions_reader@example.com")
	ownerSession, ownerToken := extStaffSession(t, app, "test@example.com")

	customer := oauth2FindRecord(t, app, "users", "test@example.com")
	customerSession, customerToken := ownSessionToken(t, app, customer)
	otherCustomerSession, _ := ownSessionToken(t, app, customer)

	b := newOAuth2Browser(t, app)
	end := func(token string, id string) (*http.Response, string) {
		headers := map[string]string{}
		if token != "" {
			headers["Authorization"] = token
		}
		return b.do(http.MethodPost, "/api/sessions/"+id+"/end", "", headers)
	}

	t.Run("guest", func(t *testing.T) {
		res, body := end("", customerSession.Id)
		b.expectStatus(res, body, http.StatusUnauthorized)
	})

	t.Run("customer", func(t *testing.T) {
		res, body := end(customerToken, otherCustomerSession.Id)
		b.expectStatus(res, body, http.StatusForbidden)
	})

	t.Run("staff with only sessions read", func(t *testing.T) {
		res, body := end(readerToken, customerSession.Id)
		b.expectStatus(res, body, http.StatusForbidden)
		if !oauth2ReloadSession(t, app, customerSession.Id).IsActive() {
			t.Fatal("Expected the customer session to remain active")
		}
	})

	t.Run("limited staff cannot end an Owner session", func(t *testing.T) {
		for _, id := range []string{ownerSession.Id, ownerSession.Parent()} {
			res, body := end(writerToken, id)
			b.expectStatus(res, body, http.StatusForbidden)
		}
		if !oauth2ReloadSession(t, app, ownerSession.Id).IsActive() {
			t.Fatal("Expected the Owner session to remain active")
		}
		res, body := b.do(http.MethodGet, "/api/permissions/me", "", map[string]string{"Authorization": ownerToken})
		b.expectStatus(res, body, http.StatusOK)
	})

	t.Run("missing session", func(t *testing.T) {
		res, body := end(writerToken, "missing")
		b.expectStatus(res, body, http.StatusNotFound)
	})

	t.Run("limited staff (sessions write) ends a customer session", func(t *testing.T) {
		// the root SSO session (cascade to its non-offline child)
		res, body := end(writerToken, customerSession.Parent())
		b.expectStatus(res, body, http.StatusNoContent)

		if oauth2ReloadSession(t, app, customerSession.Parent()).Status() != core.AuthSessionStatusEnded ||
			oauth2ReloadSession(t, app, customerSession.Id).Status() != core.AuthSessionStatusEnded {
			t.Fatal("Expected the customer root and child sessions to be ended")
		}

		res, body = b.do(http.MethodGet, "/api/permissions/me", "", map[string]string{"Authorization": customerToken})
		b.expectStatus(res, body, http.StatusUnauthorized)

		// the other customer session is untouched
		if !oauth2ReloadSession(t, app, otherCustomerSession.Id).IsActive() {
			t.Fatal("Expected the other customer session to remain active")
		}
	})

	t.Run("Owner ends a limited staff session", func(t *testing.T) {
		writerSession, _ := extStaffSession(t, app, "sessions_writer@example.com")

		res, body := end(ownerToken, writerSession.Id)
		b.expectStatus(res, body, http.StatusNoContent)

		if oauth2ReloadSession(t, app, writerSession.Id).Status() != core.AuthSessionStatusEnded {
			t.Fatal("Expected the staff session to be ended")
		}
	})
}
