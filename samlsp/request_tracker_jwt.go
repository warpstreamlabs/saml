package samlsp

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml"
)

var defaultJWTSigningMethod = jwt.SigningMethodRS256

// JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs
type JWTTrackedRequestCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           *rsa.PrivateKey
}

var _ TrackedRequestCodec = JWTTrackedRequestCodec{}

// JWTTrackedRequestClaims represents the JWT claims for a tracked request.
type JWTTrackedRequestClaims struct {
	jwt.RegisteredClaims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// Encode returns an encoded string representing the TrackedRequest.
func (s JWTTrackedRequestCodec) Encode(value TrackedRequest) (string, error) {
	now := saml.TimeNow()
	claims := JWTTrackedRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{s.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.MaxAge)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.Issuer,
			NotBefore: jwt.NewNumericDate(now), // TODO(ross): correct for clock skew
			Subject:   value.Index,
		},
		TrackedRequest:   value,
		SAMLAuthnRequest: true,
	}
	token := jwt.NewWithClaims(s.SigningMethod, claims)
	return token.SignedString(s.Key)
}

// Decode returns a Tracked request from an encoded string.
func (s JWTTrackedRequestCodec) Decode(signed string) (*TrackedRequest, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{s.SigningMethod.Alg()}),
		jwt.WithAudience(s.Audience),
		jwt.WithIssuer(s.Issuer),
	)
	claims := JWTTrackedRequestClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return s.Key.Public(), nil
	})

	if err != nil {
		return nil, err
	}
	if !claims.SAMLAuthnRequest {
		return nil, fmt.Errorf("expected saml-authn-request")
	}
	claims.TrackedRequest.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
