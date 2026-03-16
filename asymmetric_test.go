package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwt "github.com/TakuyaYagam1/go-jwtkit"
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

func testAsymmetricRoundtrip(t *testing.T, svc *jwt.JWTServiceAsymmetric) {
	t.Helper()
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	claims, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, jwt.TokenTypeAccess, claims.TokenType)
}

func TestNewJWTServiceAsymmetric_RS256(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustRSAKeyPair(t)
	refreshPriv, refreshPub := mustRSAKeyPair(t)
	svc, err := jwt.NewJWTServiceAsymmetric(
		[]jwt.AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		[]jwt.AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	require.NoError(t, err)
	testAsymmetricRoundtrip(t, svc)
}

func TestNewJWTServiceAsymmetric_ECDSA(t *testing.T) {
	t.Parallel()
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			accessPriv, accessPub := mustECDSAKeyPair(t, tc.curve)
			refreshPriv, refreshPub := mustECDSAKeyPair(t, tc.curve)
			svc, err := jwt.NewJWTServiceAsymmetric(
				[]jwt.AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
				[]jwt.AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
				time.Hour, time.Hour, testIssuer, nil, nil, "")
			require.NoError(t, err)
			testAsymmetricRoundtrip(t, svc)
		})
	}
}

func TestNewJWTServiceAsymmetric_EdDSA(t *testing.T) {
	t.Parallel()
	accessPriv, accessPub := mustEd25519KeyPair(t)
	refreshPriv, refreshPub := mustEd25519KeyPair(t)
	svc, err := jwt.NewJWTServiceAsymmetric(
		[]jwt.AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: accessPub}},
		[]jwt.AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	require.NoError(t, err)
	testAsymmetricRoundtrip(t, svc)
}

func TestNewJWTServiceAsymmetric_InvalidKeyPair(t *testing.T) {
	t.Parallel()
	rsaPriv, _ := mustRSAKeyPair(t)
	_, ecPub := mustECDSAKeyPair(t, elliptic.P256())
	_, err := jwt.NewJWTServiceAsymmetric(
		[]jwt.AsymmetricKeyEntry{{Kid: "a1", PrivateKey: rsaPriv, PublicKey: ecPub}},
		[]jwt.AsymmetricKeyEntry{{Kid: "r1", PrivateKey: rsaPriv, PublicKey: &rsaPriv.PublicKey}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	require.Error(t, err)
}
