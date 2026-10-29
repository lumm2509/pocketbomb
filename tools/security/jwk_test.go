package security_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/security"
)

func TestGeneratePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		alg         string
		expectError bool
	}{
		{"", true},
		{"HS256", true},
		{"ES512", true},
		{security.JWTAlgRS256, false},
		{security.JWTAlgES256, false},
	}

	for _, s := range scenarios {
		t.Run(s.alg, func(t *testing.T) {
			raw, err := security.GeneratePrivateKeyPEM(s.alg)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				return
			}

			if !strings.HasPrefix(raw, "-----BEGIN PRIVATE KEY-----") {
				t.Fatalf("Expected PKCS #8 PEM, got\n%s", raw)
			}

			key, err := security.ParsePrivateKeyPEM(raw)
			if err != nil {
				t.Fatal(err)
			}

			if err := security.CheckPrivateKeyAlg(key, s.alg); err != nil {
				t.Fatalf("Expected key compatible with %q, got %v", s.alg, err)
			}
		})
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1Raw, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1 := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1Raw}))

	pkcs8, err := security.GeneratePrivateKeyPEM(security.JWTAlgES256)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		pem         string
		expectError bool
	}{
		{"empty", "", true},
		{"invalid", "test", true},
		{"invalid block content", "-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----", true},
		{"PKCS #1", pkcs1, false},
		{"SEC 1", sec1, false},
		{"PKCS #8", pkcs8, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			key, err := security.ParsePrivateKeyPEM(s.pem)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if !hasErr && key == nil {
				t.Fatal("Expected non-nil key")
			}
		})
	}
}

func TestCheckPrivateKeyAlg(t *testing.T) {
	t.Parallel()

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		key         crypto.Signer
		alg         string
		expectError bool
	}{
		{"RS256 with RSA 1024", rsa1024, security.JWTAlgRS256, true},
		{"RS256 with RSA 2048", rsa2048, security.JWTAlgRS256, false},
		{"RS256 with P-256", p256, security.JWTAlgRS256, true},
		{"ES256 with RSA 2048", rsa2048, security.JWTAlgES256, true},
		{"ES256 with P-384", p384, security.JWTAlgES256, true},
		{"ES256 with P-256", p256, security.JWTAlgES256, false},
		{"unknown alg", p256, "HS256", true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			err := security.CheckPrivateKeyAlg(s.key, s.alg)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}
		})
	}
}

func TestNewJWK(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name         string
		alg          string
		key          any
		expectError  bool
		expectFields []string
	}{
		{"RSA with ES256", security.JWTAlgES256, &rsaKey.PublicKey, true, nil},
		{"EC with RS256", security.JWTAlgRS256, &ecKey.PublicKey, true, nil},
		{"unsupported key", security.JWTAlgRS256, "test", true, nil},
		{
			"RSA",
			security.JWTAlgRS256,
			&rsaKey.PublicKey,
			false,
			[]string{`"kty":"RSA"`, `"kid":"test_kid"`, `"use":"sig"`, `"alg":"RS256"`, `"n":"`, `"e":"AQAB"`},
		},
		{
			"EC",
			security.JWTAlgES256,
			&ecKey.PublicKey,
			false,
			[]string{`"kty":"EC"`, `"kid":"test_kid"`, `"use":"sig"`, `"alg":"ES256"`, `"crv":"P-256"`, `"x":"`, `"y":"`},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			jwk, err := security.NewJWK("test_kid", s.alg, s.key)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				return
			}

			raw, err := json.Marshal(jwk)
			if err != nil {
				t.Fatal(err)
			}
			rawStr := string(raw)

			for _, f := range s.expectFields {
				if !strings.Contains(rawStr, f) {
					t.Fatalf("Missing %s in\n%s", f, rawStr)
				}
			}

			if strings.Contains(rawStr, `"d"`) {
				t.Fatalf("The private exponent must not be exported:\n%s", rawStr)
			}

			// roundtrip
			pub, err := jwk.PublicKey()
			if err != nil {
				t.Fatal(err)
			}

			switch k := s.key.(type) {
			case *rsa.PublicKey:
				if !k.Equal(pub) {
					t.Fatal("Expected the decoded RSA public key to match")
				}
			case *ecdsa.PublicKey:
				if !k.Equal(pub) {
					t.Fatal("Expected the decoded ECDSA public key to match")
				}
			}
		})
	}
}

func TestJWKPublicKeyInvalid(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name string
		jwk  *security.JWK
	}{
		{"unknown kty", &security.JWK{Kty: "oct"}},
		{"RSA missing n", &security.JWK{Kty: "RSA", E: "AQAB"}},
		{"RSA invalid e", &security.JWK{Kty: "RSA", N: "AQAB", E: "!"}},
		{"EC unknown crv", &security.JWK{Kty: "EC", Crv: "P-384"}},
		{"EC short coordinates", &security.JWK{Kty: "EC", Crv: "P-256", X: "AQAB", Y: "AQAB"}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			if _, err := s.jwk.PublicKey(); err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestJWKSetFind(t *testing.T) {
	t.Parallel()

	set := &security.JWKSet{Keys: []*security.JWK{{Kid: "a"}, {Kid: "b"}}}

	if k := set.Find("b"); k == nil || k.Kid != "b" {
		t.Fatalf("Expected to find key b, got %v", k)
	}

	if k := set.Find("c"); k != nil {
		t.Fatalf("Expected nil, got %v", k)
	}
}
