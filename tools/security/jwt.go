package security

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverifiedJWT parses JWT and returns its claims
// but DOES NOT verify the signature.
//
// It verifies only the exp, iat and nbf claims.
func ParseUnverifiedJWT(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parser := &jwt.Parser{}
	_, _, err := parser.ParseUnverified(token, claims)

	if err == nil {
		err = jwt.NewValidator(jwt.WithIssuedAt()).Validate(claims)
	}

	return claims, err
}

// ParseJWT verifies and parses JWT and returns its claims.
func ParseJWT(token string, verificationKey string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(verificationKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}

// NewJWT generates and returns new HS256 signed JWT.
func NewJWT(payload jwt.MapClaims, signingKey string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		// @todo consider with the refactoring to either remove the
		// duration argument or make it always take precedence?
		"exp": time.Now().Add(duration).Unix(),
	}

	for k, v := range payload {
		claims[k] = v
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
}

// JWTSigner defines an asymmetric JWT signing key.
type JWTSigner struct {
	// Kid is the key identifier that is set as "kid" token header.
	Kid string

	// Alg is the JWT signing algorithm (RS256 or ES256).
	Alg string

	// Key is the RSA or ECDSA private key used for signing.
	Key crypto.Signer
}

func jwtSigningMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case JWTAlgRS256:
		return jwt.SigningMethodRS256, nil
	case JWTAlgES256:
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

// NewSignedJWT generates and returns new asymmetrically signed JWT (RS256 or ES256)
// with "kid" header from the provided signer.
//
// Similar to [NewJWT], the "exp" claim is set based on the duration
// (unless already set in the payload).
func NewSignedJWT(payload jwt.MapClaims, signer *JWTSigner, duration time.Duration) (string, error) {
	return newSignedJWT(payload, signer, duration, "")
}

// NewSignedJWTWithType is similar to [NewSignedJWT] but also sets the provided
// explicit "typ" token header (RFC 8725 section 3.11), e.g. so that a dedicated
// token kind can't be confused with another token signed with the same key.
func NewSignedJWTWithType(payload jwt.MapClaims, signer *JWTSigner, duration time.Duration, typ string) (string, error) {
	if typ == "" {
		return "", errors.New("missing token typ")
	}

	return newSignedJWT(payload, signer, duration, typ)
}

func newSignedJWT(payload jwt.MapClaims, signer *JWTSigner, duration time.Duration, typ string) (string, error) {
	if signer == nil || signer.Key == nil {
		return "", errors.New("missing signer key")
	}

	method, err := jwtSigningMethod(signer.Alg)
	if err != nil {
		return "", err
	}

	if err := CheckPrivateKeyAlg(signer.Key, signer.Alg); err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(duration).Unix(),
	}

	for k, v := range payload {
		claims[k] = v
	}

	token := jwt.NewWithClaims(method, claims)
	if signer.Kid != "" {
		token.Header["kid"] = signer.Kid
	}
	if typ != "" {
		token.Header["typ"] = typ
	}

	return token.SignedString(signer.Key)
}

// ParseSignedJWT verifies and parses asymmetrically signed JWT (RS256 or ES256)
// using the public key from keySet matching the token "kid" header.
//
// The token "alg" header must match with the "alg" of the resolved JWK.
//
// Optional extra parser options could be provided, e.g. jwt.WithoutClaimsValidation()
// to skip the exp claim check (as in the case of OpenID Connect id_token_hint).
func ParseSignedJWT(token string, keySet *JWKSet, extraParserOpts ...jwt.ParserOption) (jwt.MapClaims, error) {
	return parseSignedJWT(token, keySet, "", extraParserOpts...)
}

// ParseSignedJWTWithType is similar to [ParseSignedJWT] but the token must also
// have the provided explicit "typ" header (see [NewSignedJWTWithType]).
func ParseSignedJWTWithType(token string, keySet *JWKSet, typ string, extraParserOpts ...jwt.ParserOption) (jwt.MapClaims, error) {
	if typ == "" {
		return nil, errors.New("missing expected token typ")
	}

	return parseSignedJWT(token, keySet, typ, extraParserOpts...)
}

func parseSignedJWT(token string, keySet *JWKSet, typ string, extraParserOpts ...jwt.ParserOption) (jwt.MapClaims, error) {
	if keySet == nil {
		return nil, errors.New("missing key set")
	}

	parserOpts := append([]jwt.ParserOption{jwt.WithValidMethods([]string{JWTAlgRS256, JWTAlgES256})}, extraParserOpts...)

	parser := jwt.NewParser(parserOpts...)

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		if typ != "" {
			if v, _ := t.Header["typ"].(string); v != typ {
				return nil, fmt.Errorf("invalid token typ %q", v)
			}
		}

		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid header")
		}

		jwk := keySet.Find(kid)
		if jwk == nil {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}

		if jwk.Alg != t.Method.Alg() {
			return nil, fmt.Errorf("token alg %q doesn't match with the key alg %q", t.Method.Alg(), jwk.Alg)
		}

		return jwk.PublicKey()
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}
