package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/types"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/spf13/cast"
)

func TestNewInstallerToken(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := user.NewInstallerToken(time.Minute); err == nil {
		t.Fatal("Expected the installer token to be issued only for superusers")
	}

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	token, err := superuser.NewInstallerToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	claims, _ := security.ParseUnverifiedJWT(token)
	if claims[core.TokenClaimType] != core.TokenTypeInstaller || claims[core.TokenClaimId] != superuser.Id {
		t.Fatalf("Unexpected installer token claims %v", claims)
	}

	exp := cast.ToInt64(claims["exp"])
	if expected := time.Now().Add(time.Minute).Unix(); exp < expected-2 || exp > expected+2 {
		t.Fatalf("Expected exp ~%d, got %d", expected, exp)
	}

	// valid only as installer token
	if found, err := app.FindAuthRecordByToken(token, core.TokenTypeInstaller); err != nil || found.Id != superuser.Id {
		t.Fatalf("Expected valid installer token, got %v", err)
	}

	// never accepted as auth token
	if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the installer token to be rejected as auth token")
	}

	// forged auth type with the installer signing key is rejected
	forged, err := security.NewJWT(map[string]any{
		core.TokenClaimType:         core.TokenTypeAuth,
		core.TokenClaimId:           superuser.Id,
		core.TokenClaimCollectionId: superuser.Collection().Id,
	}, superuser.TokenKey()+superuser.Collection().AuthToken.Secret+".installer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(forged); err == nil {
		t.Fatal("Expected the forged token to be rejected")
	}
}

func TestSidlessAuthTokenIsRejected(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// valid signature and claims but without auth session
	token, err := security.NewJWT(map[string]any{
		core.TokenClaimType:         core.TokenTypeAuth,
		core.TokenClaimId:           user.Id,
		core.TokenClaimCollectionId: user.Collection().Id,
	}, user.TokenKey()+user.Collection().AuthToken.Secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the sid-less auth token to be rejected")
	}
}

func TestNewVerificationToken(t *testing.T) {
	t.Parallel()

	testRecordToken(t, core.TokenTypeVerification, func(record *core.Record) (string, error) {
		return record.NewVerificationToken()
	}, nil)
}

func TestNewPasswordResetToken(t *testing.T) {
	t.Parallel()

	testRecordToken(t, core.TokenTypePasswordReset, func(record *core.Record) (string, error) {
		return record.NewPasswordResetToken()
	}, nil)
}

func TestNewEmailChangeToken(t *testing.T) {
	t.Parallel()

	testRecordToken(t, core.TokenTypeEmailChange, func(record *core.Record) (string, error) {
		return record.NewEmailChangeToken("new@example.com")
	}, nil)
}

func TestNewFileToken(t *testing.T) {
	t.Parallel()

	testRecordToken(t, core.TokenTypeFile, func(record *core.Record) (string, error) {
		return record.NewFileToken()
	}, nil)
}

func testRecordToken(
	t *testing.T,
	tokenType string,
	tokenFunc func(record *core.Record) (string, error),
	expectedClaims map[string]any,
) {
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

	t.Run("non-auth record", func(t *testing.T) {
		_, err = tokenFunc(demo1)
		if err == nil {
			t.Fatal("Expected error for non-auth records")
		}
	})

	t.Run("auth record", func(t *testing.T) {
		token, err := tokenFunc(user)
		if err != nil {
			t.Fatal(err)
		}

		tokenRecord, _ := app.FindAuthRecordByToken(token, tokenType)
		if tokenRecord == nil || tokenRecord.Id != user.Id {
			t.Fatalf("Expected auth record\n%v\ngot\n%v", user, tokenRecord)
		}

		if len(expectedClaims) > 0 {
			claims, _ := security.ParseUnverifiedJWT(token)
			for k, v := range expectedClaims {
				if claims[k] != v {
					t.Errorf("Expected claim %q with value %#v, got %#v", k, v, claims[k])
				}
			}
		}
	})

	t.Run("empty signing key", func(t *testing.T) {
		user.SetTokenKey("")
		collection := user.Collection()
		*collection = core.Collection{}
		collection.Type = core.CollectionTypeAuth

		_, err := tokenFunc(user)
		if err == nil {
			t.Fatal("Expected empty signing key error")
		}
	})
}

func TestNewOIDCIdToken(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.OAuth2.MappedFields.Name = "name"
	users.OAuth2.MappedFields.Username = "username"
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	demo1, err := app.FindRecordById("demo1", "84nmscqy84lsi1t")
	if err != nil {
		t.Fatal(err)
	}

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user.Set("name", "test_name")
	user.Set("username", "test_username")
	user.SetVerified(true)
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	clientsUser, err := app.FindAuthRecordByEmail("clients", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// every saved auth collection has a signing key so simulate a missing one in memory
	clientsUser.Collection().OAuth2Server.SigningKeys = nil

	client := stubOAuth2Client(t, app, "users", "client1")

	authTime := types.NowDateTime().Add(-1 * time.Hour)
	session := stubAuthSession(t, app, client, user, []string{"openid", "profile"})
	session.SetAuthTime(authTime)

	issuer := core.OAuth2Issuer(app, users)

	jwks, err := users.OAuth2Server.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	activeKey, _ := users.OAuth2Server.ActiveSigningKey()

	scenarios := []struct {
		name           string
		record         *core.Record
		opts           core.OIDCIdTokenOptions
		expectError    bool
		expectClaims   map[string]any
		expectNoClaims []string
	}{
		{
			"non-auth record",
			demo1,
			core.OIDCIdTokenOptions{Issuer: issuer, Client: client},
			true,
			nil,
			nil,
		},
		{
			"missing issuer",
			user,
			core.OIDCIdTokenOptions{Client: client},
			true,
			nil,
			nil,
		},
		{
			"missing client",
			user,
			core.OIDCIdTokenOptions{Issuer: issuer},
			true,
			nil,
			nil,
		},
		{
			"collection without signing key",
			clientsUser,
			core.OIDCIdTokenOptions{Issuer: issuer, Client: client},
			true,
			nil,
			nil,
		},
		{
			"minimal",
			user,
			core.OIDCIdTokenOptions{Issuer: issuer, Client: client, Scopes: []string{"openid"}},
			false,
			map[string]any{
				"iss": issuer,
				"sub": user.Id,
				"aud": "client1",
			},
			[]string{"email", "email_verified", "name", "nonce", "sid", "auth_time", "type", "collectionId"},
		},
		{
			"with email scope and nonce",
			user,
			core.OIDCIdTokenOptions{
				Issuer:   issuer,
				Client:   client,
				Scopes:   []string{"openid", "email"},
				Nonce:    "test_nonce",
				AuthTime: authTime,
			},
			false,
			map[string]any{
				"email":          "test@example.com",
				"email_verified": true,
				"nonce":          "test_nonce",
				"auth_time":      float64(authTime.Unix()),
			},
			[]string{"name", "sid"},
		},
		{
			"with session fallbacks and extra claims",
			user,
			core.OIDCIdTokenOptions{
				Issuer:  issuer,
				Client:  client,
				Session: session,
				ExtraClaims: map[string]any{
					"custom": "abc",
					"iss":    "override_attempt",
					"sub":    "override_attempt",
					"sid":    "override_attempt",
				},
			},
			false,
			map[string]any{
				"iss":                issuer,
				"sub":                user.Id,
				"sid":                session.Id,
				"auth_time":          float64(authTime.Unix()),
				"name":               "test_name",
				"preferred_username": "test_username",
				"custom":             "abc",
			},
			[]string{"email"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			token, err := s.record.NewOIDCIdToken(s.opts)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				return
			}

			// verify with the public JWKS
			claims, err := security.ParseSignedJWT(token, jwks)
			if err != nil {
				t.Fatal(err)
			}

			parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Header["kid"] != activeKey.Kid || parsed.Header["alg"] != activeKey.Alg {
				t.Fatalf("Expected kid %q and alg %q headers, got %v", activeKey.Kid, activeKey.Alg, parsed.Header)
			}

			if _, ok := claims["iat"]; !ok {
				t.Fatal("Missing iat claim")
			}

			exp := cast.ToInt64(claims["exp"])
			expectedExp := time.Now().Add(users.AuthToken.DurationTime()).Unix()
			if exp < expectedExp-5 || exp > expectedExp+5 {
				t.Fatalf("Expected exp ~%d, got %d", expectedExp, exp)
			}

			for k, v := range s.expectClaims {
				if claims[k] != v {
					t.Errorf("Expected claim %q with value %#v, got %#v", k, v, claims[k])
				}
			}

			for _, k := range s.expectNoClaims {
				if _, ok := claims[k]; ok {
					t.Errorf("Expected claim %q to be missing", k)
				}
			}

			// shouldn't be usable as regular auth token
			if _, err := app.FindAuthRecordByToken(token); err == nil {
				t.Fatal("Expected the id_token to not be accepted as auth token")
			}
		})
	}
}

func TestRecordOIDCStandardClaims(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.OAuth2.MappedFields.Name = "name"
	users.OAuth2.MappedFields.Username = "username"
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		scopes   []string
		expected []string
	}{
		{nil, []string{"sub"}},
		{[]string{"openid"}, []string{"sub"}},
		{[]string{"openid", "email"}, []string{"sub", "email", "email_verified"}},
		{[]string{"profile"}, []string{"sub", "name", "preferred_username", "updated_at"}},
	}

	for _, s := range scenarios {
		t.Run(strings.Join(s.scopes, "_"), func(t *testing.T) {
			claims := user.OIDCStandardClaims(s.scopes)

			if len(claims) != len(s.expected) {
				t.Fatalf("Expected claims %v, got %v", s.expected, claims)
			}

			for _, k := range s.expected {
				if _, ok := claims[k]; !ok {
					t.Fatalf("Missing claim %q in %v", k, claims)
				}
			}

			if claims["sub"] != user.Id {
				t.Fatalf("Expected sub %q, got %v", user.Id, claims["sub"])
			}
		})
	}
}
