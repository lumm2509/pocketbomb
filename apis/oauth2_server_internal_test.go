package apis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/auth"

	_ "github.com/lumm2509/pocketbomb/migrations"
)

// newInternalTestApp initializes a fresh app instance for the package apis
// internal tests (the package can't import the tests package because of an import cycle).
func newInternalTestApp(t testing.TB) *core.BaseApp {
	t.Helper()

	app := core.NewBaseApp(core.BaseAppConfig{
		DataDir:       t.TempDir(),
		EncryptionEnv: "pb_test_env",
	})

	if err := app.Bootstrap(); err != nil {
		t.Fatalf("Failed to bootstrap the internal test app: %v", err)
	}

	t.Cleanup(func() {
		_ = app.ResetBootstrapState()
	})

	return app
}

func newInternalAuthCollection(t testing.TB, app core.App, name string, fields ...core.Field) *core.Collection {
	t.Helper()

	collection := core.NewAuthCollection(name)

	for _, field := range fields {
		collection.Fields.Add(field)
	}

	if err := app.Save(collection); err != nil {
		t.Fatalf("Failed to save the %q collection: %v", name, err)
	}

	return collection
}

func TestParseAppleRedirectName(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		result, err := parseAppleRedirectName("")
		if err != nil || result != "" {
			t.Fatalf("Expected empty result, got %q (%v)", result, err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		result, err := parseAppleRedirectName(strings.Repeat("a", 5001))
		if err != nil || result != "" {
			t.Fatalf("Expected too large data to be ignored, got %q (%v)", result, err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		if _, err := parseAppleRedirectName(`{"name":`); err == nil {
			t.Fatal("Expected invalid json error")
		}
	})

	scenarios := []struct {
		name     string
		raw      string
		expected string
	}{
		{"first and last name", `{"name":{"firstName":"John","lastName":"Doe"}}`, "John Doe"},
		{"first name only", `{"name":{"firstName":"John"}}`, "John"},
		{"last name only", `{"name":{"lastName":"Doe"}}`, "Doe"},
		{"no name", `{}`, ""},
		{"blank name", `{"name":{"firstName":"  ","lastName":"  "}}`, ""},
		{
			"truncated to 150 chars",
			`{"name":{"firstName":"` + strings.Repeat("a", 100) + `","lastName":"` + strings.Repeat("b", 100) + `"}}`,
			strings.Repeat("a", 100) + " " + strings.Repeat("b", 49),
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result, err := parseAppleRedirectName(s.raw)
			if err != nil {
				t.Fatal(err)
			}
			if result != s.expected {
				t.Fatalf("Expected %q, got %q", s.expected, result)
			}
			if len(result) > 150 {
				t.Fatalf("Expected the name to be truncated to max 150 chars, got %d", len(result))
			}
		})
	}
}

func TestOAuth2RenderLabels(t *testing.T) {
	t.Parallel()

	collection := core.NewAuthCollection("render_users")

	t.Run("user label", func(t *testing.T) {
		if result := oauth2UserLabel(nil); result != "" {
			t.Fatalf("Expected an empty nil label, got %q", result)
		}

		record := core.NewRecord(collection)
		record.Id = "record_id"
		if result := oauth2UserLabel(record); result != "record_id" {
			t.Fatalf("Expected the record id fallback, got %q", result)
		}

		record.SetEmail("user@example.com")
		if result := oauth2UserLabel(record); result != "user@example.com" {
			t.Fatalf("Expected the record email, got %q", result)
		}
	})

	t.Run("identity label", func(t *testing.T) {
		collection.PasswordAuth.IdentityFields = nil
		if result := oauth2IdentityLabel(collection); result != "Email" {
			t.Fatalf("Expected the default Email label, got %q", result)
		}

		collection.PasswordAuth.IdentityFields = []string{""}
		if result := oauth2IdentityLabel(collection); result != "" {
			t.Fatalf("Expected an empty label, got %q", result)
		}

		collection.PasswordAuth.IdentityFields = []string{"username"}
		if result := oauth2IdentityLabel(collection); result != "Username" {
			t.Fatalf("Expected the capitalized field label, got %q", result)
		}

		collection.PasswordAuth.IdentityFields = []string{"username", "email"}
		if result := oauth2IdentityLabel(collection); result != "Username or email" {
			t.Fatalf("Expected the joined field labels, got %q", result)
		}
	})
}

func TestOAuth2RenderPageError(t *testing.T) {
	t.Parallel()

	app := newInternalTestApp(t)
	collection := core.NewAuthCollection("render_users")

	e := &core.RequestEvent{App: app}
	e.Response = httptest.NewRecorder()
	e.Request = httptest.NewRequest(http.MethodGet, "/oauth2/render_users/login", nil)

	// unknown page names are reported as internal server errors
	if err := oauth2RenderPage(e, collection, http.StatusOK, "oauth2/non_existing_page", nil); err == nil {
		t.Fatal("Expected a render error")
	}

	// the invalid form helper renders the generic error page
	recorder := httptest.NewRecorder()
	e.Response = recorder
	if err := oauth2RenderInvalidFormPage(e, collection, errors.New("invalid form")); err != nil {
		t.Fatalf("Expected a successful error page render, got %v", err)
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "Invalid or expired form submission") {
		t.Fatalf("Expected the invalid form message, got %s", body)
	}
}

func TestOldCanAssignUsername(t *testing.T) {
	t.Parallel()

	t.Run("missing field", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_missing")

		collection.OAuth2.MappedFields.Username = "missing"
		if oldCanAssignUsername(app, collection, "any") {
			t.Fatal("Expected false for a missing mapped field")
		}

		collection.OAuth2.MappedFields.Username = ""
		if oldCanAssignUsername(app, collection, "any") {
			t.Fatal("Expected false for an empty mapped field")
		}
	})

	t.Run("non text field without unique index", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_number",
			&core.NumberField{Name: "username"},
		)

		collection.OAuth2.MappedFields.Username = "username"
		if !oldCanAssignUsername(app, collection, "any") {
			t.Fatal("Expected true for a non-text field without unique index")
		}
	})

	t.Run("text field pattern", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_pattern",
			&core.TextField{Name: "username", Pattern: `^[a-z]+$`},
		)

		collection.OAuth2.MappedFields.Username = "username"
		if oldCanAssignUsername(app, collection, "UPPER") {
			t.Fatal("Expected false for a value not matching the field pattern")
		}
		if !oldCanAssignUsername(app, collection, "lower") {
			t.Fatal("Expected true for a valid value")
		}
	})

	t.Run("text field without unique index", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_no_index",
			&core.TextField{Name: "username"},
		)

		collection.OAuth2.MappedFields.Username = "username"
		if !oldCanAssignUsername(app, collection, "any") {
			t.Fatal("Expected true without a unique index")
		}
	})

	t.Run("case sensitive unique index", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_case",
			&core.TextField{Name: "username"},
		)
		collection.Indexes = append(
			collection.Indexes,
			"CREATE UNIQUE INDEX `idx_old_username_case` ON `old_username_case` (`username`)",
		)
		if err := app.Save(collection); err != nil {
			t.Fatal(err)
		}

		record := core.NewRecord(collection)
		record.Set("username", "CaseUser")
		record.SetEmail("case@example.com")
		record.SetPassword("1234567890")
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}

		collection.OAuth2.MappedFields.Username = "username"
		if oldCanAssignUsername(app, collection, "CaseUser") {
			t.Fatal("Expected false for an existing case-sensitive username")
		}
		if !oldCanAssignUsername(app, collection, "caseuser") {
			t.Fatal("Expected true for a case-sensitive non-existing username")
		}
	})

	t.Run("nocase unique index", func(t *testing.T) {
		app := newInternalTestApp(t)
		collection := newInternalAuthCollection(t, app, "old_username_nocase",
			&core.TextField{Name: "username"},
		)
		collection.Indexes = append(
			collection.Indexes,
			"CREATE UNIQUE INDEX `idx_old_username_nocase` ON `old_username_nocase` (`username` COLLATE NOCASE)",
		)
		if err := app.Save(collection); err != nil {
			t.Fatal(err)
		}

		record := core.NewRecord(collection)
		record.Set("username", "NoCaseUser")
		record.SetEmail("nocase@example.com")
		record.SetPassword("1234567890")
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}

		collection.OAuth2.MappedFields.Username = "username"
		if oldCanAssignUsername(app, collection, "nocaseuser") {
			t.Fatal("Expected false for an existing nocase username")
		}
		if !oldCanAssignUsername(app, collection, "otheruser") {
			t.Fatal("Expected true for a non-existing nocase username")
		}
	})
}

func TestFindOAuth2UpstreamRecord(t *testing.T) {
	t.Parallel()

	app := newInternalTestApp(t)
	collection := newInternalAuthCollection(t, app, "upstream_users")

	record1 := core.NewRecord(collection)
	record1.SetEmail("first@example.com")
	record1.SetPassword("1234567890")
	if err := app.Save(record1); err != nil {
		t.Fatal(err)
	}

	record2 := core.NewRecord(collection)
	record2.SetEmail("second@example.com")
	record2.SetPassword("1234567890")
	if err := app.Save(record2); err != nil {
		t.Fatal(err)
	}

	externalAuth := core.NewExternalAuth(app)
	externalAuth.SetCollectionRef(collection.Id)
	externalAuth.SetRecordRef(record1.Id)
	externalAuth.SetProvider(auth.NameGoogle)
	externalAuth.SetProviderId("external_id")
	if err := app.Save(externalAuth); err != nil {
		t.Fatal(err)
	}

	t.Run("existing external auth", func(t *testing.T) {
		record, rel, err := findOAuth2UpstreamRecord(app, collection, auth.NameGoogle, &auth.AuthUser{Id: "external_id"})
		if err != nil {
			t.Fatal(err)
		}
		if record == nil || record.Id != record1.Id {
			t.Fatalf("Expected the linked record, got %v", record)
		}
		if rel == nil || rel.Id != externalAuth.Id {
			t.Fatalf("Expected the external auth relation, got %v", rel)
		}
	})

	t.Run("email match", func(t *testing.T) {
		record, rel, err := findOAuth2UpstreamRecord(app, collection, auth.NameGoogle, &auth.AuthUser{
			Id:    "unknown_external_id",
			Email: record2.Email(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if record == nil || record.Id != record2.Id {
			t.Fatalf("Expected the email matched record, got %v", record)
		}
		if rel != nil {
			t.Fatalf("Expected no external auth relation, got %v", rel)
		}
	})

	t.Run("no match", func(t *testing.T) {
		record, rel, err := findOAuth2UpstreamRecord(app, collection, auth.NameGoogle, &auth.AuthUser{Id: "missing_id"})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if record != nil || rel != nil {
			t.Fatalf("Expected no match, got %v / %v", record, rel)
		}
	})

	t.Run("invalid external auth relation", func(t *testing.T) {
		dangling := core.NewExternalAuth(app)
		dangling.SetCollectionRef(collection.Id)
		dangling.SetRecordRef("missing_record")
		dangling.SetProvider(auth.NameGoogle)
		dangling.SetProviderId("dangling_id")
		if err := app.SaveNoValidate(dangling); err != nil {
			t.Fatal(err)
		}

		if _, _, err := findOAuth2UpstreamRecord(app, collection, auth.NameGoogle, &auth.AuthUser{Id: "dangling_id"}); err == nil {
			t.Fatal("Expected a missing record error")
		}
	})
}

func TestSaveOAuth2UpstreamRecordRejectsSuperusers(t *testing.T) {
	t.Parallel()

	app := newInternalTestApp(t)

	superusers, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}

	e := &core.RequestEvent{App: app}

	_, err = saveOAuth2UpstreamRecord(context.Background(), e, superusers, auth.NameGoogle, &auth.AuthUser{Id: "superuser_id"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "superusers are not allowed") {
		t.Fatalf("Expected superuser rejection, got %v", err)
	}
}

func TestSafeFileFromURLErrors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("invalid url", func(t *testing.T) {
		if _, err := safeFileFromURL(ctx, "://invalid-url"); err == nil {
			t.Fatal("Expected an invalid url error")
		}
	})

	t.Run("loopback host", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, _ = res.Write([]byte("avatar"))
		}))
		defer server.Close()

		if _, err := safeFileFromURL(ctx, server.URL+"/avatar.png"); err == nil {
			t.Fatal("Expected the loopback url to be rejected")
		}
	})

	// NB: the non-2xx, oversized body and success paths require a reachable
	// public host and are intentionally not exercised here (see the report).
}

func TestFindOAuth2UpstreamRecordQueryError(t *testing.T) {
	t.Parallel()

	app := newInternalTestApp(t)
	collection := newInternalAuthCollection(t, app, "upstream_query_error")

	// dropping the external auths table forces a non sql.ErrNoRows query error
	if _, err := app.DB().NewQuery("DROP TABLE " + core.CollectionNameExternalAuths).Execute(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := findOAuth2UpstreamRecord(app, collection, auth.NameGoogle, &auth.AuthUser{Id: "id"}); err == nil {
		t.Fatal("Expected the external auth query error to be returned")
	}
}
