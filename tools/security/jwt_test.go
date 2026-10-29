package security_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/security"
)

func TestParseUnverifiedJWT(t *testing.T) {
	// invalid formatted JWT
	result1, err1 := security.ParseUnverifiedJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9")
	if err1 == nil {
		t.Error("Expected error got nil")
	}
	if len(result1) > 0 {
		t.Error("Expected no parsed claims, got", result1)
	}

	// properly formatted JWT with INVALID claims
	// {"name": "test", "exp":1516239022}
	result2, err2 := security.ParseUnverifiedJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTUxNjIzOTAyMn0.xYHirwESfSEW3Cq2BL47CEASvD_p_ps3QCA54XtNktU")
	if err2 == nil {
		t.Error("Expected error got nil")
	}
	if len(result2) != 2 || result2["name"] != "test" {
		t.Errorf("Expected to have 2 claims, got %v", result2)
	}

	// properly formatted JWT with VALID claims (missing exp)
	// {"name": "test"}
	result3, err3 := security.ParseUnverifiedJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.ml0QsTms3K9wMygTu41ZhKlTyjmW9zHQtoS8FUsCCjU")
	if err3 != nil {
		t.Error("Expected nil, got", err3)
	}
	if len(result3) != 1 || result3["name"] != "test" {
		t.Errorf("Expected to have 1 claim, got %v", result3)
	}

	// properly formatted JWT with VALID claims (valid exp)
	// {"name": "test", "exp": 2524604461}
	result4, err4 := security.ParseUnverifiedJWT("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MjUyNDYwNDQ2MX0.VIEO73GP5QRQOSfHgQhaqeuYqcx59vL3xlxmFP-fytQ")
	if err4 != nil {
		t.Error("Expected nil, got", err4)
	}
	if len(result4) != 2 || result4["name"] != "test" {
		t.Errorf("Expected to have 2 claims, got %v", result4)
	}
}

func TestParseJWT(t *testing.T) {
	scenarios := []struct {
		name         string
		token        string
		secret       string
		expectError  bool
		expectClaims jwt.MapClaims
	}{
		{
			"invalid formatted JWT",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9",
			"test",
			true,
			nil,
		},
		{
			"properly formatted JWT with INVALID claims and INVALID secret",
			// {"name": "test", "exp": 1516239022}
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTUxNjIzOTAyMn0.xYHirwESfSEW3Cq2BL47CEASvD_p_ps3QCA54XtNktU",
			"invalid",
			true,
			nil,
		},
		{
			"properly formatted JWT with INVALID claims and VALID secret",
			// {"name": "test", "exp": 1516239022}
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTUxNjIzOTAyMn0.xYHirwESfSEW3Cq2BL47CEASvD_p_ps3QCA54XtNktU",
			"test",
			true,
			nil,
		},
		{
			"properly formatted JWT with VALID claims and INVALID secret",
			// {"name": "test", "exp": 2524604461}
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MjUyNDYwNDQ2MX0.VIEO73GP5QRQOSfHgQhaqeuYqcx59vL3xlxmFP-fytQ",
			"invalid",
			true,
			nil,
		},
		{
			"properly formatted JWT with VALID claims and VALID secret",
			// {"name": "test", "exp": 2524604461}
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MjUyNDYwNDQ2MX0.VIEO73GP5QRQOSfHgQhaqeuYqcx59vL3xlxmFP-fytQ",
			"test",
			false,
			jwt.MapClaims{"name": "test", "exp": 2524604461.0},
		},
		{
			"properly formatted JWT with VALID claims (without exp) and VALID secret",
			// {"name": "test"}
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.ml0QsTms3K9wMygTu41ZhKlTyjmW9zHQtoS8FUsCCjU",
			"test",
			false,
			jwt.MapClaims{"name": "test"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result, err := security.ParseJWT(s.token, s.secret)

			hasErr := err != nil

			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if len(result) != len(s.expectClaims) {
				t.Fatalf("Expected %v claims got %v", s.expectClaims, result)
			}

			for k, v := range s.expectClaims {
				v2, ok := result[k]
				if !ok {
					t.Fatalf("Missing expected claim %q", k)
				}
				if v != v2 {
					t.Fatalf("Expected %v for %q claim, got %v", v, k, v2)
				}
			}
		})
	}
}

func TestNewJWT(t *testing.T) {
	scenarios := []struct {
		name        string
		claims      jwt.MapClaims
		key         string
		duration    time.Duration
		expectError bool
	}{
		{"empty, zero duration", jwt.MapClaims{}, "", 0, true},
		{"empty, 10 seconds duration", jwt.MapClaims{}, "", 10 * time.Second, false},
		{"non-empty, 10 seconds duration", jwt.MapClaims{"name": "test"}, "test", 10 * time.Second, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			token, tokenErr := security.NewJWT(s.claims, s.key, s.duration)
			if tokenErr != nil {
				t.Fatalf("Expected NewJWT to succeed, got error %v", tokenErr)
			}

			claims, parseErr := security.ParseJWT(token, s.key)

			hasParseErr := parseErr != nil
			if hasParseErr != s.expectError {
				t.Fatalf("Expected hasParseErr to be %v, got %v (%v)", s.expectError, hasParseErr, parseErr)
			}

			if s.expectError {
				return
			}

			if _, ok := claims["exp"]; !ok {
				t.Fatalf("Missing required claim exp, got %v", claims)
			}

			// clear exp claim to match with the scenario ones
			delete(claims, "exp")

			if len(claims) != len(s.claims) {
				t.Fatalf("Expected %v claims, got %v", s.claims, claims)
			}

			for k, v := range claims {
				if v != s.claims[k] {
					t.Fatalf("Expected %v for %q claim, got %v", s.claims[k], k, v)
				}
			}
		})
	}
}

func TestNewAndParseSignedJWT(t *testing.T) {
	t.Parallel()

	newSigner := func(kid, alg string) *security.JWTSigner {
		raw, err := security.GeneratePrivateKeyPEM(alg)
		if err != nil {
			t.Fatal(err)
		}
		key, err := security.ParsePrivateKeyPEM(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &security.JWTSigner{Kid: kid, Alg: alg, Key: key}
	}

	rsaSigner := newSigner("rsa_kid", security.JWTAlgRS256)
	ecSigner := newSigner("ec_kid", security.JWTAlgES256)
	otherSigner := newSigner("rsa_kid", security.JWTAlgRS256) // same kid but different key

	newJWK := func(s *security.JWTSigner) *security.JWK {
		jwk, err := security.NewJWK(s.Kid, s.Alg, s.Key.Public())
		if err != nil {
			t.Fatal(err)
		}
		return jwk
	}

	keySet := &security.JWKSet{Keys: []*security.JWK{newJWK(rsaSigner), newJWK(ecSigner)}}

	// key set with mismatched alg for the same kid
	algMismatchJWK := newJWK(ecSigner)
	algMismatchJWK.Alg = security.JWTAlgRS256
	algMismatchSet := &security.JWKSet{Keys: []*security.JWK{algMismatchJWK}}

	hs256, err := security.NewJWT(jwt.MapClaims{"a": "b"}, "test", 1*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		signer      *security.JWTSigner
		duration    time.Duration
		keySet      *security.JWKSet
		token       string // if set, the signer is ignored
		expectError bool
	}{
		{"RS256", rsaSigner, 1 * time.Minute, keySet, "", false},
		{"ES256", ecSigner, 1 * time.Minute, keySet, "", false},
		{"expired", rsaSigner, -1 * time.Minute, keySet, "", true},
		{"missing key set", rsaSigner, 1 * time.Minute, nil, "", true},
		{"unknown kid", &security.JWTSigner{Kid: "missing", Alg: rsaSigner.Alg, Key: rsaSigner.Key}, 1 * time.Minute, keySet, "", true},
		{"missing kid", &security.JWTSigner{Alg: rsaSigner.Alg, Key: rsaSigner.Key}, 1 * time.Minute, keySet, "", true},
		{"wrong key with known kid", otherSigner, 1 * time.Minute, keySet, "", true},
		{"alg mismatch", &security.JWTSigner{Kid: ecSigner.Kid, Alg: ecSigner.Alg, Key: ecSigner.Key}, 1 * time.Minute, algMismatchSet, "", true},
		{"HS256 token", nil, 0, keySet, hs256, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			token := s.token
			if token == "" {
				var err error
				token, err = security.NewSignedJWT(jwt.MapClaims{"name": "test"}, s.signer, s.duration)
				if err != nil {
					t.Fatal(err)
				}

				unverified, _ := security.ParseUnverifiedJWT(token)
				if unverified["name"] != "test" {
					t.Fatalf("Expected name claim, got %v", unverified)
				}

				header := strings.Split(token, ".")[0]
				rawHeader, err := base64.RawURLEncoding.DecodeString(header)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(rawHeader), `"alg":"`+s.signer.Alg+`"`) {
					t.Fatalf("Expected alg %q header, got %s", s.signer.Alg, rawHeader)
				}
				if s.signer.Kid != "" && !strings.Contains(string(rawHeader), `"kid":"`+s.signer.Kid+`"`) {
					t.Fatalf("Expected kid %q header, got %s", s.signer.Kid, rawHeader)
				}
			}

			claims, err := security.ParseSignedJWT(token, s.keySet)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if !hasErr && claims["name"] != "test" {
				t.Fatalf("Expected name claim, got %v", claims)
			}
		})
	}
}

func TestNewSignedJWTInvalidSigner(t *testing.T) {
	t.Parallel()

	ecRaw, err := security.GeneratePrivateKeyPEM(security.JWTAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := security.ParsePrivateKeyPEM(ecRaw)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name   string
		signer *security.JWTSigner
	}{
		{"nil signer", nil},
		{"nil key", &security.JWTSigner{Alg: security.JWTAlgES256}},
		{"unsupported alg", &security.JWTSigner{Alg: "HS256", Key: ecKey}},
		{"key and alg mismatch", &security.JWTSigner{Alg: security.JWTAlgRS256, Key: ecKey}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			if _, err := security.NewSignedJWT(jwt.MapClaims{}, s.signer, time.Minute); err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestParseSignedJWTExtraParserOptions(t *testing.T) {
	t.Parallel()

	pem, err := security.GeneratePrivateKeyPEM(security.JWTAlgES256)
	if err != nil {
		t.Fatal(err)
	}

	key, err := security.ParsePrivateKeyPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := security.NewJWK("test", security.JWTAlgES256, key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keySet := &security.JWKSet{Keys: []*security.JWK{jwk}}

	expired, err := security.NewSignedJWT(jwt.MapClaims{"sub": "123"}, &security.JWTSigner{Kid: "test", Alg: security.JWTAlgES256, Key: key}, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := security.ParseSignedJWT(expired, keySet); err == nil {
		t.Fatal("Expected the expired token to fail without extra parser options")
	}

	claims, err := security.ParseSignedJWT(expired, keySet, jwt.WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("Expected the expired token to be parsed with WithoutClaimsValidation, got %v", err)
	}
	if claims["sub"] != "123" {
		t.Fatalf("Expected sub 123, got %v", claims["sub"])
	}

	// the signature is still verified
	if _, err := security.ParseSignedJWT(expired+"a", keySet, jwt.WithoutClaimsValidation()); err == nil {
		t.Fatal("Expected the tampered token to fail")
	}
}

func TestNewAndParseSignedJWTWithType(t *testing.T) {
	t.Parallel()

	raw, err := security.GeneratePrivateKeyPEM(security.JWTAlgRS256)
	if err != nil {
		t.Fatal(err)
	}
	key, err := security.ParsePrivateKeyPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	signer := &security.JWTSigner{Kid: "typ_kid", Alg: security.JWTAlgRS256, Key: key}

	jwk, err := security.NewJWK(signer.Kid, signer.Alg, key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keySet := &security.JWKSet{Keys: []*security.JWK{jwk}}

	if _, err := security.NewSignedJWTWithType(jwt.MapClaims{}, signer, time.Minute, ""); err == nil {
		t.Fatal("Expected the empty typ to be rejected")
	}

	typed, err := security.NewSignedJWTWithType(jwt.MapClaims{"name": "test"}, signer, time.Minute, "test+jwt")
	if err != nil {
		t.Fatal(err)
	}

	untyped, err := security.NewSignedJWT(jwt.MapClaims{"name": "test"}, signer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	otherTyped, err := security.NewSignedJWTWithType(jwt.MapClaims{"name": "test"}, signer, time.Minute, "other+jwt")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		token       string
		typ         string
		expectError bool
	}{
		{"matching typ", typed, "test+jwt", false},
		{"missing typ header", untyped, "test+jwt", true},
		{"other typ header", otherTyped, "test+jwt", true},
		{"empty expected typ", typed, "", true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			claims, err := security.ParseSignedJWTWithType(s.token, keySet, s.typ)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if !hasErr && claims["name"] != "test" {
				t.Fatalf("Expected name claim, got %v", claims)
			}
		})
	}

	// the typed tokens are still valid regular signed tokens
	if _, err := security.ParseSignedJWT(typed, keySet); err != nil {
		t.Fatalf("Expected the typed token to be a valid signed token, got %v", err)
	}
}
