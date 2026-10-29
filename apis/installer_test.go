package apis_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func installerToken(t testing.TB, app core.App) string {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}

	installer, err := app.FindAuthRecordByEmail(collection, core.DefaultInstallerEmail)
	if err != nil {
		installer = core.NewRecord(collection)
		installer.SetEmail(core.DefaultInstallerEmail)
		installer.SetRandomPassword()
		if err := app.Save(installer); err != nil {
			t.Fatal(err)
		}
	}

	token, err := installer.NewInstallerToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func TestInstallerApi(t *testing.T) {
	t.Parallel()

	// fresh app without explicit superusers (aka. the installer state)
	newInstallerApp := func(t testing.TB) *tests.TestApp {
		app, err := tests.NewTestApp()
		if err != nil {
			t.Fatal(err)
		}

		// ensure that the system installer superuser exists
		installerToken(t, app)

		// remove the Owner assignments (bypassing the last Owner invariant) to simulate a fresh install
		if _, err := app.DB().Delete(core.CollectionNameRoleAssignments, nil).Execute(); err != nil {
			t.Fatal(err)
		}

		superusers, err := app.FindAllRecords(core.CollectionNameSuperusers)
		if err != nil {
			t.Fatal(err)
		}
		for _, su := range superusers {
			if su.Email() == core.DefaultInstallerEmail {
				continue
			}
			if err := app.Delete(su); err != nil {
				t.Fatal(err)
			}
		}

		return app
	}

	t.Run("missing or invalid installer token", func(t *testing.T) {
		app := newInstallerApp(t)
		defer app.Cleanup()

		b := newOAuth2Browser(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		userToken, _ := tests.NewSessionAuthToken(app, user)

		for name, token := range map[string]string{
			"missing":    "",
			"invalid":    "invalid",
			"auth token": userToken,
		} {
			res, body := b.do(http.MethodPost, "/api/installer", `{"email":"new@example.com","password":"1234567890","passwordConfirm":"1234567890"}`, map[string]string{
				"Content-Type":  "application/json",
				"Authorization": token,
			})
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("[%s] Expected 401, got %d %s", name, res.StatusCode, body)
			}
		}
	})

	t.Run("create the first superuser", func(t *testing.T) {
		app := newInstallerApp(t)
		defer app.Cleanup()

		token := installerToken(t, app)

		b := newOAuth2Browser(t, app)

		// the installer token is never accepted as auth token
		res, _ := b.do(http.MethodGet, "/api/collections/_superusers/records", "", map[string]string{"Authorization": token})
		if res.StatusCode == http.StatusOK {
			t.Fatal("Expected the installer token to be rejected as auth token")
		}

		// validation errors
		res, body := b.do(http.MethodPost, "/api/installer", `{"email":"invalid","password":"1","passwordConfirm":"2"}`, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
		})
		b.expectStatus(res, body, http.StatusBadRequest)

		res, body = b.do(http.MethodPost, "/api/installer", `{"email":"owner@example.com","password":"1234567890","passwordConfirm":"1234567890"}`, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
		})
		b.expectStatus(res, body, http.StatusNoContent)

		owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "owner@example.com")
		if err != nil || !owner.ValidatePassword("1234567890") {
			t.Fatalf("Expected the new superuser, got %v", err)
		}

		// the system installer superuser is deleted and the installer is no longer available
		if _, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, core.DefaultInstallerEmail); err == nil {
			t.Fatal("Expected the installer superuser to be deleted")
		}

		res, body = b.do(http.MethodPost, "/api/installer", `{"email":"another@example.com","password":"1234567890","passwordConfirm":"1234567890"}`, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
		})
		if res.StatusCode == http.StatusNoContent {
			t.Fatalf("Expected the installer to be unavailable, got %d %s", res.StatusCode, body)
		}

		// the new superuser signs in with OAuth2 (pb_dashboard)
		b.startLogin(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
			"redirect_uri": "http://localhost:8090/_/",
			"scope":        "openid email",
		})
		res = b.loginPassword(core.CollectionNameSuperusers, "owner@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, "http://localhost:8090/_/?", map[string]string{"code": "*", "state": "test_state"})
	})

	t.Run("installer is not available when an explicit superuser exists", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		token := installerToken(t, app)

		b := newOAuth2Browser(t, app)
		res, _ := b.do(http.MethodPost, "/api/installer", `{"email":"owner@example.com","password":"1234567890","passwordConfirm":"1234567890"}`, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": token,
		})
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", res.StatusCode)
		}
	})

}
