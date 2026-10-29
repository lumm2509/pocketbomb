package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Supported asymmetric JWT signing algorithms.
const (
	JWTAlgRS256 = "RS256"
	JWTAlgES256 = "ES256"
)

// rsaKeyBits is the size of the auto generated RSA keys.
const rsaKeyBits = 2048

// GeneratePrivateKeyPEM generates a new private key suitable for the
// specified JWT signing algorithm (RS256 or ES256) and returns it
// encoded as PKCS #8 PEM block.
func GeneratePrivateKeyPEM(alg string) (string, error) {
	var key crypto.Signer
	var err error

	switch alg {
	case JWTAlgRS256:
		key, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	case JWTAlgES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	if err != nil {
		return "", err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParsePrivateKeyPEM parses a PEM encoded RSA or ECDSA private key
// (PKCS #8, PKCS #1 or SEC 1).
func ParsePrivateKeyPEM(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid or missing PEM block")
	}

	var key any
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

// CheckPrivateKeyAlg checks whether the private key is suitable for the specified JWT signing algorithm.
func CheckPrivateKeyAlg(key crypto.Signer, alg string) error {
	switch alg {
	case JWTAlgRS256:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("RS256 requires RSA private key")
		}
		if k.N.BitLen() < rsaKeyBits {
			return fmt.Errorf("RS256 requires RSA private key with at least %d bits", rsaKeyBits)
		}
	case JWTAlgES256:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k.Curve != elliptic.P256() {
			return errors.New("ES256 requires ECDSA P-256 private key")
		}
	default:
		return fmt.Errorf("unsupported signing algorithm %q", alg)
	}

	return nil
}

// -------------------------------------------------------------------

// JWK defines a public JSON Web Key as described in RFC 7517 and RFC 7518.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg"`

	// RSA public key components
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC public key components
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// NewJWK creates a new public signature JWK from the provided RSA or ECDSA public key.
func NewJWK(kid string, alg string, publicKey crypto.PublicKey) (*JWK, error) {
	jwk := &JWK{Kid: kid, Alg: alg, Use: "sig"}

	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		if alg != JWTAlgRS256 {
			return nil, fmt.Errorf("RSA public key is not compatible with %q", alg)
		}
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		if alg != JWTAlgES256 || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ECDSA public key is not compatible with %q", alg)
		}
		raw, err := k.Bytes() // uncompressed form 0x04 || X || Y
		if err != nil {
			return nil, err
		}
		size := (len(raw) - 1) / 2
		jwk.Kty = "EC"
		jwk.Crv = "P-256"
		jwk.X = base64.RawURLEncoding.EncodeToString(raw[1 : 1+size])
		jwk.Y = base64.RawURLEncoding.EncodeToString(raw[1+size:])
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}

	return jwk, nil
}

// PublicKey decodes and returns the JWK as RSA or ECDSA public key.
func (k *JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("invalid JWK n: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("invalid JWK e: %w", err)
		}
		eInt := new(big.Int).SetBytes(e)
		if len(n) == 0 || !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64() > 1<<31-1 {
			return nil, errors.New("invalid JWK RSA public key components")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported JWK curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("invalid JWK x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid JWK y: %w", err)
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("invalid JWK EC public key components")
		}
		raw := append(append([]byte{4}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}

// JWKSet defines a JSON Web Key Set as described in RFC 7517 (section 5).
type JWKSet struct {
	Keys []*JWK `json:"keys"`
}

// Find returns the first JWK with the specified kid (or nil if not found).
func (s *JWKSet) Find(kid string) *JWK {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k
		}
	}

	return nil
}
