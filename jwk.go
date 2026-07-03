package jwtkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

const (
	jwkUseSignature = "sig"
	jwkKtyRSA       = "RSA"
	jwkKtyEC        = "EC"
	jwkKtyOKP       = "OKP"
	jwkCrvEd25519   = "Ed25519" //nolint:usestdlibvars // JWK curve identifier, not a TLS signature scheme.

	jwtSigningMethodRS256 = "RS256"
	jwtSigningMethodES256 = "ES256"
	jwtSigningMethodES384 = "ES384"
	jwtSigningMethodES512 = "ES512"
	jwtSigningMethodEdDSA = "EdDSA"
)

type ecdsaJWKCurve struct {
	curve elliptic.Curve
	alg   string
	crv   string
	size  int
}

// PublicJWK is an RFC 7517 public JSON Web Key for signature verification.
type PublicJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PublicJWKSet is an RFC 7517 JSON Web Key Set containing public keys.
type PublicJWKSet struct {
	Keys []PublicJWK `json:"keys"`
}

// PublicJWKFromKey converts a supported public key to a public JWK.
func PublicJWKFromKey(kid string, pub crypto.PublicKey) (PublicJWK, error) {
	if kid == "" {
		return PublicJWK{}, errors.New("jwk kid is required")
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := validateRSAPublicKey(k); err != nil {
			return PublicJWK{}, err
		}
		return PublicJWK{
			Kty: jwkKtyRSA,
			Use: jwkUseSignature,
			Kid: kid,
			Alg: jwtSigningMethodRS256,
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		params, err := jwkECDSACurve(k.Curve)
		if err != nil {
			return PublicJWK{}, err
		}
		point, err := k.Bytes()
		if err != nil {
			return PublicJWK{}, fmt.Errorf("ECDSA public key encode: %w", err)
		}
		if len(point) != 1+2*params.size || point[0] != 4 {
			return PublicJWK{}, errors.New("ECDSA public key must encode as an uncompressed point")
		}
		x := point[1 : 1+params.size]
		y := point[1+params.size:]
		return PublicJWK{
			Kty: jwkKtyEC,
			Use: jwkUseSignature,
			Kid: kid,
			Alg: params.alg,
			Crv: params.crv,
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
		}, nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return PublicJWK{}, fmt.Errorf("Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
		}
		return PublicJWK{
			Kty: jwkKtyOKP,
			Use: jwkUseSignature,
			Kid: kid,
			Alg: jwtSigningMethodEdDSA,
			Crv: jwkCrvEd25519,
			X:   base64.RawURLEncoding.EncodeToString(k),
		}, nil
	default:
		return PublicJWK{}, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// PublicKeyFromJWK converts a supported public JWK to a Go public key.
func PublicKeyFromJWK(key PublicJWK) (crypto.PublicKey, error) {
	switch key.Kty {
	case jwkKtyRSA:
		return publicKeyFromRSAJWK(key)
	case jwkKtyEC:
		return publicKeyFromECJWK(key)
	case jwkKtyOKP:
		return publicKeyFromOKPJWK(key)
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", key.Kty)
	}
}

// PublicJWKSetFromKeys exports public JWKs from asymmetric key entries.
func PublicJWKSetFromKeys(keys []AsymmetricKeyEntry) (PublicJWKSet, error) {
	seen := make(map[string]struct{}, len(keys))
	out := PublicJWKSet{Keys: make([]PublicJWK, 0, len(keys))}
	for _, key := range keys {
		if key.Kid == "" {
			return PublicJWKSet{}, errors.New("jwk kid is required")
		}
		if _, ok := seen[key.Kid]; ok {
			return PublicJWKSet{}, fmt.Errorf("duplicate JWK kid %q", key.Kid)
		}
		seen[key.Kid] = struct{}{}
		jwk, err := PublicJWKFromKey(key.Kid, key.PublicKey)
		if err != nil {
			return PublicJWKSet{}, fmt.Errorf("jwk %q: %w", key.Kid, err)
		}
		out.Keys = append(out.Keys, jwk)
	}
	return out, nil
}

// PublicKeysFromJWKSet imports public keys from a JWK set, keyed by kid.
func PublicKeysFromJWKSet(set PublicJWKSet) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kid == "" {
			return nil, errors.New("jwk kid is required")
		}
		if _, ok := out[jwk.Kid]; ok {
			return nil, fmt.Errorf("duplicate JWK kid %q", jwk.Kid)
		}
		pub, err := PublicKeyFromJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: %w", jwk.Kid, err)
		}
		out[jwk.Kid] = pub
	}
	return out, nil
}

func validateRSAPublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil {
		return errors.New("RSA public key is required")
	}
	if pub.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf("RSA key must be at least %d bits", minRSAKeyBits)
	}
	if pub.E < 3 || pub.E%2 == 0 {
		return errors.New("RSA public key exponent must be an odd integer >= 3")
	}
	return nil
}

func publicKeyFromRSAJWK(key PublicJWK) (crypto.PublicKey, error) {
	if key.Alg != "" && key.Alg != jwtSigningMethodRS256 {
		return nil, fmt.Errorf("unsupported RSA JWK alg %q", key.Alg)
	}
	nBytes, err := decodeJWKField(key.N, "n")
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeJWKField(key.E, "e")
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("RSA JWK exponent is too large")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}
	if err := validateRSAPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func publicKeyFromECJWK(key PublicJWK) (crypto.PublicKey, error) {
	params, err := curveFromJWK(key.Crv)
	if err != nil {
		return nil, err
	}
	if key.Alg != "" && key.Alg != params.alg {
		return nil, fmt.Errorf("unsupported %s JWK alg %q", key.Crv, key.Alg)
	}
	xBytes, err := decodeJWKField(key.X, "x")
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeJWKField(key.Y, "y")
	if err != nil {
		return nil, err
	}
	if len(xBytes) != params.size || len(yBytes) != params.size {
		return nil, fmt.Errorf("ECDSA JWK coordinates must be %d bytes", params.size)
	}
	point := make([]byte, 1+2*params.size)
	point[0] = 4
	copy(point[1:1+params.size], xBytes)
	copy(point[1+params.size:], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(params.curve, point)
	if err != nil {
		return nil, fmt.Errorf("ECDSA JWK public key parse: %w", err)
	}
	return pub, nil
}

func publicKeyFromOKPJWK(key PublicJWK) (crypto.PublicKey, error) {
	if key.Crv != jwkCrvEd25519 {
		return nil, fmt.Errorf("unsupported OKP JWK curve %q", key.Crv)
	}
	if key.Alg != "" && key.Alg != jwtSigningMethodEdDSA {
		return nil, fmt.Errorf("unsupported Ed25519 JWK alg %q", key.Alg)
	}
	xBytes, err := decodeJWKField(key.X, "x")
	if err != nil {
		return nil, err
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 JWK x must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(xBytes), nil
}

func jwkECDSACurve(curve elliptic.Curve) (ecdsaJWKCurve, error) {
	if curve == nil {
		return ecdsaJWKCurve{}, errors.New("ECDSA public key requires non-nil Curve")
	}
	switch curve.Params().Name {
	case CurveP256:
		return ecdsaJWKCurve{curve: curve, alg: jwtSigningMethodES256, crv: CurveP256, size: 32}, nil
	case CurveP384:
		return ecdsaJWKCurve{curve: curve, alg: jwtSigningMethodES384, crv: CurveP384, size: 48}, nil
	case CurveP521:
		return ecdsaJWKCurve{curve: curve, alg: jwtSigningMethodES512, crv: CurveP521, size: 66}, nil
	default:
		return ecdsaJWKCurve{}, fmt.Errorf("unsupported ECDSA curve %q", curve.Params().Name)
	}
}

func curveFromJWK(crv string) (ecdsaJWKCurve, error) {
	switch crv {
	case CurveP256:
		return ecdsaJWKCurve{curve: elliptic.P256(), alg: jwtSigningMethodES256, crv: CurveP256, size: 32}, nil
	case CurveP384:
		return ecdsaJWKCurve{curve: elliptic.P384(), alg: jwtSigningMethodES384, crv: CurveP384, size: 48}, nil
	case CurveP521:
		return ecdsaJWKCurve{curve: elliptic.P521(), alg: jwtSigningMethodES512, crv: CurveP521, size: 66}, nil
	default:
		return ecdsaJWKCurve{}, fmt.Errorf("unsupported EC JWK curve %q", crv)
	}
}

func decodeJWKField(value, name string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("JWK field %q is required", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode JWK field %q: %w", name, err)
	}
	return decoded, nil
}
