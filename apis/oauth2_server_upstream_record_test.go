package apis_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
)

// oauth2StartUpstreamLogin starts a hosted flow and returns the browser
// and the upstream callback response.
func oauth2StartUpstreamLogin(t testing.TB, app *tests.TestApp, code string) (*oauth2Browser, *http.Response) {
	t.Helper()

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	state, _ := oauth2StartUpstream(t, b)

	res, _ := b.get("/api/oauth2-redirect?code=" + code + "&state=" + url.QueryEscape(state))

	return b, res
}

func oauth2ExpectUpstreamFailure(t testing.TB, res *http.Response) {
	t.Helper()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("Expected a redirect, got %d", res.StatusCode)
	}
	if location := res.Header.Get("Location"); !strings.Contains(location, "error=upstream") {
		t.Fatalf("Expected an upstream error redirect, got %q", location)
	}
}

func TestOAuth2ServerUpstreamRecordMappings(t *testing.T) {
	t.Parallel()

	upstream := oauth2FakeUpstreamInstance()

	t.Run("create with mapped id, username and text avatar url", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			oauth2EnableFakeProvider(c)
			c.Fields.Add(&core.TextField{Name: "avatar_url"})
			c.OAuth2.MappedFields.Id = "name"
			c.OAuth2.MappedFields.Username = "username"
			c.OAuth2.MappedFields.AvatarURL = "avatar_url"
		})

		email := "mapped_" + security.RandomString(6) + "@example.com"
		code := "mapped_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:        "mapped_external_id",
			Email:     email,
			Name:      "Ignored Name",
			Username:  "mapped_user_" + security.RandomString(6),
			AvatarURL: "https://cdn.example.com/avatar.png",
		})

		b, res := oauth2StartUpstreamLogin(t, app, code)
		b.expectStatus(res, "", http.StatusFound)
		res, _ = b.follow(res)
		b.expectCode(res, oauth2TestIssuer)

		record := oauth2FindRecord(t, app, "users", email)
		if record.GetString("name") != "mapped_external_id" {
			t.Fatalf("Expected the mapped id field, got %q", record.GetString("name"))
		}
		if !strings.HasPrefix(record.GetString("username"), "mapped_user_") {
			t.Fatalf("Expected the mapped username, got %q", record.GetString("username"))
		}
		if record.GetString("avatar_url") != "https://cdn.example.com/avatar.png" {
			t.Fatalf("Expected the mapped avatar url, got %q", record.GetString("avatar_url"))
		}
		if !record.Verified() {
			t.Fatal("Expected the record to be verified")
		}

		ea, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{
			"provider":   oauth2FakeProviderName,
			"providerId": "mapped_external_id",
		})
		if err != nil || ea.RecordRef() != record.Id {
			t.Fatalf("Expected the external auth link, got %v (%v)", ea, err)
		}
	})

	t.Run("create with mapped file avatar url download failure", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			oauth2EnableFakeProvider(c)
			c.Fields.Add(&core.FileField{Name: "avatar_file", MaxSelect: 1})
			c.OAuth2.MappedFields.AvatarURL = "avatar_file"
		})

		email := "avatar_" + security.RandomString(6) + "@example.com"
		code := "avatar_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:        "avatar_external_id",
			Email:     email,
			Name:      "Avatar User",
			AvatarURL: "http://127.0.0.1:1/avatar.png",
		})

		b, res := oauth2StartUpstreamLogin(t, app, code)
		b.expectStatus(res, "", http.StatusFound)
		res, _ = b.follow(res)
		b.expectCode(res, oauth2TestIssuer)

		record := oauth2FindRecord(t, app, "users", email)
		if record.GetString("avatar_file") != "" {
			t.Fatalf("Expected no downloaded avatar file, got %q", record.GetString("avatar_file"))
		}
	})
}

func TestOAuth2ServerUpstreamRecordPreHijackAndUpdates(t *testing.T) {
	t.Parallel()

	upstream := oauth2FakeUpstreamInstance()

	t.Run("unverified existing record is hardened", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		users, err := app.FindCollectionByNameOrId("users")
		if err != nil {
			t.Fatal(err)
		}

		email := "prehijack_" + security.RandomString(6) + "@example.com"

		record := core.NewRecord(users)
		record.SetEmail(email)
		record.SetPassword("1234567890")
		record.Set("username", "prehijack_"+security.RandomString(6))
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}

		oldPasswordHash := record.GetString("password:hash")

		oldLink := core.NewExternalAuth(app)
		oldLink.SetCollectionRef(users.Id)
		oldLink.SetRecordRef(record.Id)
		oldLink.SetProvider(auth.NameGoogle)
		oldLink.SetProviderId("old_provider_id")
		if err := app.Save(oldLink); err != nil {
			t.Fatal(err)
		}

		code := "prehijack_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:    "prehijack_external_id",
			Email: email,
			Name:  "Pre Hijack",
		})

		b, res := oauth2StartUpstreamLogin(t, app, code)
		b.expectStatus(res, "", http.StatusFound)
		res, _ = b.follow(res)
		b.expectCode(res, oauth2TestIssuer)

		updated, err := app.FindRecordById("users", record.Id)
		if err != nil {
			t.Fatal(err)
		}
		if !updated.Verified() {
			t.Fatal("Expected the record to be verified")
		}
		if updated.GetString("password:hash") == oldPasswordHash {
			t.Fatal("Expected the unverified record password to be reset")
		}

		links, err := app.FindAllExternalAuthsByRecord(updated)
		if err != nil || len(links) != 1 || links[0].Provider() != oauth2FakeProviderName {
			t.Fatalf("Expected only the new external auth link, got %v (%v)", links, err)
		}
	})

	t.Run("existing record without email gets the upstream email", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		users, err := app.FindCollectionByNameOrId("users")
		if err != nil {
			t.Fatal(err)
		}

		record := core.NewRecord(users)
		record.SetPassword("1234567890")
		record.Set("username", "noemail_"+security.RandomString(6))
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}

		link := core.NewExternalAuth(app)
		link.SetCollectionRef(users.Id)
		link.SetRecordRef(record.Id)
		link.SetProvider(oauth2FakeProviderName)
		link.SetProviderId("empty_email_external_id")
		if err := app.Save(link); err != nil {
			t.Fatal(err)
		}

		email := "filled_" + security.RandomString(6) + "@example.com"
		code := "filled_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:    "empty_email_external_id",
			Email: email,
			Name:  "Filled Email",
		})

		b, res := oauth2StartUpstreamLogin(t, app, code)
		b.expectStatus(res, "", http.StatusFound)
		res, _ = b.follow(res)
		b.expectCode(res, oauth2TestIssuer)

		updated, err := app.FindRecordById("users", record.Id)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Email() != email {
			t.Fatalf("Expected the email to be assigned, got %q", updated.Email())
		}
		if !updated.Verified() {
			t.Fatal("Expected the record to be verified")
		}

		links, err := app.FindAllExternalAuthsByRecord(updated)
		if err != nil || len(links) != 1 || links[0].ProviderId() != "empty_email_external_id" {
			t.Fatalf("Expected a single recreated link, got %v (%v)", links, err)
		}
	})

	t.Run("verified existing record link conflict fails", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		existing := oauth2FindRecord(t, app, "users", "test2@example.com")
		if !existing.Verified() {
			t.Fatal("Expected a verified test record")
		}

		otherLink := core.NewExternalAuth(app)
		otherLink.SetCollectionRef(existing.Collection().Id)
		otherLink.SetRecordRef(existing.Id)
		otherLink.SetProvider(oauth2FakeProviderName)
		otherLink.SetProviderId("other_external_id")
		if err := app.Save(otherLink); err != nil {
			t.Fatal(err)
		}

		code := "conflict_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:    "conflict_external_id",
			Email: existing.Email(),
		})

		_, res := oauth2StartUpstreamLogin(t, app, code)
		oauth2ExpectUpstreamFailure(t, res)

		if _, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{
			"provider":   oauth2FakeProviderName,
			"providerId": "conflict_external_id",
		}); err == nil {
			t.Fatal("Expected no external auth link to be created")
		}
	})
}

func TestOAuth2ServerUpstreamRecordCreateFailures(t *testing.T) {
	t.Parallel()

	upstream := oauth2FakeUpstreamInstance()

	t.Run("create rule rejection", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			oauth2EnableFakeProvider(c)
			rule := "@request.auth.id != ''"
			c.CreateRule = &rule
		})

		email := "denied_" + security.RandomString(6) + "@example.com"
		code := "denied_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:    "denied_external_id",
			Email: email,
			Name:  "Denied User",
		})

		_, res := oauth2StartUpstreamLogin(t, app, code)
		oauth2ExpectUpstreamFailure(t, res)

		if _, err := app.FindAuthRecordByEmail("users", email); err == nil {
			t.Fatal("Expected no record to be created")
		}
	})

	t.Run("forced verification save error", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableFakeProvider)

		email := "savefail_" + security.RandomString(6) + "@example.com"
		code := "savefail_" + security.RandomString(10)
		upstream.stubUser(code, &auth.AuthUser{
			Id:    "savefail_external_id",
			Email: email,
			Name:  "Save Fail",
		})

		app.OnRecordUpdateExecute("users").Bind(&hook.Handler[*core.RecordEvent]{
			Func: func(e *core.RecordEvent) error {
				if e.Record.Email() == email {
					return errors.New("forced save error")
				}
				return e.Next()
			},
			Priority: 9999,
		})

		_, res := oauth2StartUpstreamLogin(t, app, code)
		oauth2ExpectUpstreamFailure(t, res)

		if _, err := app.FindAuthRecordByEmail("users", email); err == nil {
			t.Fatal("Expected the transaction to be rolled back")
		}
	})
}
