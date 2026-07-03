package jwtkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicJWKFromKey_RSA(t *testing.T) {
	t.Parallel()
	_, pub := mustRSAKeyPair(t)

	jwk, err := PublicJWKFromKey("rsa-1", pub)
	require.NoError(t, err)
	assert.Equal(t, jwkKtyRSA, jwk.Kty)
	assert.Equal(t, jwtSigningMethodRS256, jwk.Alg)
	assert.Equal(t, "rsa-1", jwk.Kid)
	assert.NotEmpty(t, jwk.N)
	assert.NotEmpty(t, jwk.E)

	got, err := PublicKeyFromJWK(jwk)
	require.NoError(t, err)
	gotRSA, ok := got.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pub.N, gotRSA.N)
	assert.Equal(t, pub.E, gotRSA.E)
}

func TestPublicJWKFromKey_ECDSA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		crv  elliptic.Curve
	}{
		{CurveP256, jwtSigningMethodES256, elliptic.P256()},
		{CurveP384, jwtSigningMethodES384, elliptic.P384()},
		{CurveP521, jwtSigningMethodES512, elliptic.P521()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, pub := mustECDSAKeyPair(t, tc.crv)

			jwk, err := PublicJWKFromKey("ec-1", pub)
			require.NoError(t, err)
			assert.Equal(t, jwkKtyEC, jwk.Kty)
			assert.Equal(t, tc.want, jwk.Alg)
			assert.Equal(t, tc.name, jwk.Crv)
			assert.NotEmpty(t, jwk.X)
			assert.NotEmpty(t, jwk.Y)

			got, err := PublicKeyFromJWK(jwk)
			require.NoError(t, err)
			gotECDSA, ok := got.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, pub.Curve.Params().Name, gotECDSA.Curve.Params().Name)
			assert.True(t, pub.Equal(gotECDSA))
		})
	}
}

func TestPublicJWKFromKey_Ed25519(t *testing.T) {
	t.Parallel()
	_, pub := mustEd25519KeyPair(t)

	jwk, err := PublicJWKFromKey("ed-1", pub)
	require.NoError(t, err)
	assert.Equal(t, jwkKtyOKP, jwk.Kty)
	assert.Equal(t, jwtSigningMethodEdDSA, jwk.Alg)
	assert.Equal(t, jwkCrvEd25519, jwk.Crv)
	assert.NotEmpty(t, jwk.X)

	got, err := PublicKeyFromJWK(jwk)
	require.NoError(t, err)
	gotEd, ok := got.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pub, gotEd)
}

func TestPublicJWKSetFromKeys(t *testing.T) {
	t.Parallel()
	rsaPriv, rsaPub := mustRSAKeyPair(t)
	edPriv, edPub := mustEd25519KeyPair(t)

	set, err := PublicJWKSetFromKeys([]AsymmetricKeyEntry{
		{Kid: "rsa-1", PrivateKey: rsaPriv, PublicKey: rsaPub},
		{Kid: "ed-1", PrivateKey: edPriv, PublicKey: edPub},
	})
	require.NoError(t, err)
	require.Len(t, set.Keys, 2)

	encoded, err := json.Marshal(set)
	require.NoError(t, err)
	require.JSONEq(t, `{"keys":[{"kty":"RSA","use":"sig","kid":"rsa-1","alg":"RS256","n":"`+set.Keys[0].N+`","e":"`+set.Keys[0].E+`"},{"kty":"OKP","use":"sig","kid":"ed-1","alg":"EdDSA","crv":"Ed25519","x":"`+set.Keys[1].X+`"}]}`, string(encoded))

	keys, err := PublicKeysFromJWKSet(set)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, keys["rsa-1"])
	assert.IsType(t, ed25519.PublicKey{}, keys["ed-1"])
}

func TestPublicJWKSetFromKeys_DuplicateKid(t *testing.T) {
	t.Parallel()
	priv, pub := mustEd25519KeyPair(t)
	const duplicateKid = "dup"
	_, err := PublicJWKSetFromKeys([]AsymmetricKeyEntry{
		{Kid: duplicateKid, PrivateKey: priv, PublicKey: pub},
		{Kid: duplicateKid, PrivateKey: priv, PublicKey: pub},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestPublicKeysFromJWKSet_RejectsInvalidSet(t *testing.T) {
	t.Parallel()
	_, err := PublicKeysFromJWKSet(PublicJWKSet{Keys: []PublicJWK{{Kty: jwkKtyOKP}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid")

	const duplicateKid = "dup"
	_, err = PublicKeysFromJWKSet(PublicJWKSet{Keys: []PublicJWK{
		{Kid: duplicateKid, Kty: jwkKtyOKP, Crv: jwkCrvEd25519, X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Kid: duplicateKid, Kty: jwkKtyOKP, Crv: jwkCrvEd25519, X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestPublicKeyFromJWK_RejectsInvalidKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		jwk  PublicJWK
	}{
		{name: "unsupported kty", jwk: PublicJWK{Kty: "oct"}},
		{name: "rsa invalid alg", jwk: PublicJWK{Kty: jwkKtyRSA, Alg: "RS512", N: "AA", E: "AQAB"}},
		{name: "ec unsupported curve", jwk: PublicJWK{Kty: jwkKtyEC, Crv: "P-224"}},
		{name: "ed25519 invalid size", jwk: PublicJWK{Kty: jwkKtyOKP, Crv: jwkCrvEd25519, X: "AA"}},
		{name: "invalid base64", jwk: PublicJWK{Kty: jwkKtyOKP, Crv: jwkCrvEd25519, X: "*"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := PublicKeyFromJWK(tc.jwk)
			require.Error(t, err)
		})
	}
}

func TestPublicJWKFromKey_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	_, pub := mustEd25519KeyPair(t)
	_, err := PublicJWKFromKey("", pub)
	require.Error(t, err)

	_, err = PublicJWKFromKey("bad-ed", ed25519.PublicKey("short"))
	require.Error(t, err)

	_, err = PublicJWKFromKey("unsupported", "not-a-key")
	require.Error(t, err)
}
