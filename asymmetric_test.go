package jwtkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func mustECDSAKeyPair(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func mustEd25519KeyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv, pub
}

func testAsymmetricRoundtrip(t *testing.T, svc *JWTServiceAsymmetric) {
	t.Helper()
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	claims, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, TokenTypeAccess, claims.TokenType)
}

func TestNewJWTServiceAsymmetric_RS256(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustRSAKeyPair(t)
	refreshPriv, refreshPub := mustRSAKeyPair(t)
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)
	testAsymmetricRoundtrip(t, svc)
}

func TestNewJWTServiceAsymmetric_ECDSA(t *testing.T) {
	t.Parallel()
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{CurveP256, elliptic.P256()},
		{CurveP384, elliptic.P384()},
		{CurveP521, elliptic.P521()},
	}
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			accessPriv, accessPub := mustECDSAKeyPair(t, tc.curve)
			refreshPriv, refreshPub := mustECDSAKeyPair(t, tc.curve)
			svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
				AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
				RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
				AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
			})
			require.NoError(t, err)
			testAsymmetricRoundtrip(t, svc)
		})
	}
}

func TestNewJWTServiceAsymmetric_EdDSA(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustEd25519KeyPair(t)
	refreshPriv, refreshPub := mustEd25519KeyPair(t)
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)
	testAsymmetricRoundtrip(t, svc)
}

func TestNewJWTServiceAsymmetric_InvalidKeyPair(t *testing.T) {
	t.Parallel()
	rsaPriv, _ := mustRSAKeyPair(t)
	_, ecPub := mustECDSAKeyPair(t, elliptic.P256())
	_, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: rsaPriv, PublicKey: ecPub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: rsaPriv, PublicKey: &rsaPriv.PublicKey}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.Error(t, err)
}

func TestJWTServiceAsymmetric_GenerateTokenPair_RejectsNilUserID(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustEd25519KeyPair(t)
	refreshPriv, refreshPub := mustEd25519KeyPair(t)
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)
	pair, err := svc.GenerateTokenPair(context.Background(), uuid.Nil, "user")
	require.ErrorIs(t, err, ErrNilUserID)
	assert.Nil(t, pair)
}

func TestJWTServiceAsymmetric_ValidateAccessToken_RejectsMissingKid(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustEd25519KeyPair(t)
	refreshPriv, refreshPub := mustEd25519KeyPair(t)
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)

	now := time.Now().Add(-time.Second)
	claims, _ := buildTokenPairClaims(uuid.New(), "user", testIssuer, "", now.Add(time.Hour), now.Add(24*time.Hour), now)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(accessPriv)
	require.NoError(t, err)

	got, err := svc.ValidateAccessToken(context.Background(), tokenString)
	require.ErrorIs(t, err, ErrMissingKidHeader)
	assert.Nil(t, got)
}
