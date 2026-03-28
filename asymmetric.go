package jwtkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AsymmetricKeyEntry holds a key id and a key pair for signing (private) and verification (public)
// Supported: *rsa.PrivateKey (RS256 only; RS384/RS512 not supported), *ecdsa.PrivateKey (ES256/ES384/ES512 by curve), ed25519.PrivateKey (EdDSA)
// RSA keys must be at least 2048 bits; ECDSA curves P-256, P-384, P-521. PrivateKey and PublicKey must match and pass validation
type AsymmetricKeyEntry struct {
	Kid        string            // Key identifier; non-empty, unique per slice
	PrivateKey crypto.PrivateKey // Used for signing; do not modify after passing to NewJWTServiceAsymmetric
	PublicKey  crypto.PublicKey  // Used for verification; must match PrivateKey
}

// AsymmetricConfig configures NewJWTServiceAsymmetric
// Issuer is required; AccessKeys and RefreshKeys must each contain at least one key pair
// Revoker and UserRoleLookup may be nil; RefreshTokens requires a non-nil Revoker
// StrictKid when true rejects tokens without kid header
type AsymmetricConfig struct {
	AccessKeys     []AsymmetricKeyEntry // Key pairs for access tokens; first is primary
	RefreshKeys    []AsymmetricKeyEntry // Key pairs for refresh tokens; first is primary
	AccessTTL      time.Duration        // Lifetime of access tokens; positive, ≤ MaxAccessTTL
	RefreshTTL     time.Duration        // Lifetime of refresh tokens; positive, ≤ MaxRefreshTTL
	Issuer         string               // Required; set in iss claim and validated on parse
	Audience       string               // Optional; if non-empty, aud claim is set and validated
	Revoker        RevocationStore      // Optional; required for RefreshTokens and Revoke* methods
	UserRoleLookup UserRoleLookup       // Optional; called during RefreshTokens to refresh role
	StrictKid      bool                 // If true, token must have kid header; no fallback to primary
}

// JWTServiceAsymmetric implements Service using asymmetric signing (RS256, ES256/ES384/ES512, or EdDSA)
// Use NewJWTServiceAsymmetric to construct; do not instantiate manually
type JWTServiceAsymmetric struct {
	core

	accessKeys          []AsymmetricKeyEntry
	refreshKeys         []AsymmetricKeyEntry
	accessPrimaryKid    string
	refreshPrimaryKid   string
	accessPublicByKid   map[string]crypto.PublicKey
	refreshPublicByKid  map[string]crypto.PublicKey
	accessValidMethods  []string
	refreshValidMethods []string
	issuer              string
	audience            string
}

// NewJWTServiceAsymmetric builds a JWT service with asymmetric keys from AsymmetricConfig
// Issuer must be non-empty; AccessKeys and RefreshKeys must each contain at least one valid key pair
// Key pairs are validated (RSA ≥2048 bits, ECDSA P-256/P-384/P-521, Ed25519); Kid must be non-empty and unique
// Revoker and UserRoleLookup may be nil; non-empty Audience adds aud claim and validation
// Key slices are copied but PrivateKey/PublicKey are stored by reference; do not modify key entries after construction
func NewJWTServiceAsymmetric(cfg AsymmetricConfig) (*JWTServiceAsymmetric, error) {
	if len(cfg.AccessKeys) == 0 {
		return nil, errors.New("access keys must contain at least one key")
	}
	if len(cfg.RefreshKeys) == 0 {
		return nil, errors.New("refresh keys must contain at least one key")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if cfg.AccessTTL <= 0 {
		return nil, errors.New("accessTTL must be positive")
	}
	if cfg.RefreshTTL <= 0 {
		return nil, errors.New("refreshTTL must be positive")
	}
	if cfg.AccessTTL > MaxAccessTTL {
		return nil, fmt.Errorf("accessTTL must not exceed %v", MaxAccessTTL)
	}
	if cfg.RefreshTTL > MaxRefreshTTL {
		return nil, fmt.Errorf("refreshTTL must not exceed %v", MaxRefreshTTL)
	}
	for i, k := range cfg.AccessKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("access key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("access key %q: %w", k.Kid, err)
		}
	}
	for i, k := range cfg.RefreshKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("refresh key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("refresh key %q: %w", k.Kid, err)
		}
	}
	accessPub := make(map[string]crypto.PublicKey, len(cfg.AccessKeys))
	for _, k := range cfg.AccessKeys {
		if k.Kid == "" {
			return nil, errors.New("access key Kid must be non-empty")
		}
		if _, exists := accessPub[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate access key Kid %q", k.Kid)
		}
		accessPub[k.Kid] = k.PublicKey
	}
	refreshPub := make(map[string]crypto.PublicKey, len(cfg.RefreshKeys))
	for _, k := range cfg.RefreshKeys {
		if k.Kid == "" {
			return nil, errors.New("refresh key Kid must be non-empty")
		}
		if _, exists := refreshPub[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate refresh key Kid %q", k.Kid)
		}
		refreshPub[k.Kid] = k.PublicKey
	}
	j := &JWTServiceAsymmetric{
		accessKeys:          slices.Clone(cfg.AccessKeys),
		refreshKeys:         slices.Clone(cfg.RefreshKeys),
		accessPrimaryKid:    cfg.AccessKeys[0].Kid,
		refreshPrimaryKid:   cfg.RefreshKeys[0].Kid,
		accessPublicByKid:   accessPub,
		refreshPublicByKid:  refreshPub,
		accessValidMethods:  buildValidMethodsFromKeys(cfg.AccessKeys),
		refreshValidMethods: buildValidMethodsFromKeys(cfg.RefreshKeys),
		issuer:              cfg.Issuer,
		audience:            cfg.Audience,
	}
	j.core = *newCore(
		func(ctx context.Context, s string) (*CustomClaims, error) {
			return j.rawValidateToken(ctx, s, TokenTypeAccess, j.accessPrimaryKid, j.accessPublicByKid, j.accessValidMethods, j.StrictKid())
		},
		func(ctx context.Context, s string) (*CustomClaims, error) {
			return j.rawValidateToken(ctx, s, TokenTypeRefresh, j.refreshPrimaryKid, j.refreshPublicByKid, j.refreshValidMethods, j.StrictKid())
		},
		j.GenerateTokenPair,
		cfg.Revoker,
		cfg.UserRoleLookup,
		cfg.StrictKid,
		cfg.AccessTTL,
		cfg.RefreshTTL,
	)
	return j, nil
}

const minRSAKeyBits = 2048

func validateAsymmetricKeyPair(priv crypto.PrivateKey, pub crypto.PublicKey) error {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pubRSA, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA private key requires RSA public key")
		}
		if k.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("RSA key must be at least %d bits", minRSAKeyBits)
		}
		if err := k.Validate(); err != nil {
			return fmt.Errorf("RSA key validation: %w", err)
		}
		if k.N.Cmp(pubRSA.N) != 0 || k.E != pubRSA.E {
			return errors.New("RSA public key does not match private key")
		}
		return nil
	case ed25519.PrivateKey:
		pubEd, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("Ed25519 private key requires Ed25519 public key")
		}
		signer := priv.(crypto.Signer)                                //nolint:forcetypeassert
		if !bytes.Equal(signer.Public().(ed25519.PublicKey), pubEd) { //nolint:forcetypeassert
			return errors.New("Ed25519 public key does not match private key")
		}
		return nil
	case *ecdsa.PrivateKey:
		pubECDSA, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ECDSA private key requires ECDSA public key")
		}
		if k.Curve == nil {
			return errors.New("ECDSA private key requires non-nil Curve")
		}
		if !k.PublicKey.Equal(pubECDSA) {
			return errors.New("ECDSA public key does not match private key")
		}
		switch k.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return nil
		default:
			return fmt.Errorf("unsupported ECDSA curve %q (supported: P-256, P-384, P-521)", k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("unsupported private key type %T (supported: *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey)", priv)
	}
}

// GenerateTokenPair issues a new access and refresh token pair with unique JTIs
// userID and role are stored in both tokens; algorithm is determined by the primary key (first in slice)
// Returns (*TokenPair, nil) or an error (e.g. if signing fails)
func (j *JWTServiceAsymmetric) GenerateTokenPair(_ context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(j.AccessTTL())
	refreshExpiry := now.Add(j.RefreshTTL())
	accessClaims, refreshClaims := buildTokenPairClaims(userID, role, j.issuer, j.audience, accessExpiry, refreshExpiry, now)

	accessEntry := j.accessKeys[0]
	accessMethod, err := signingMethodForKey(accessEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("access key: %w", err)
	}
	accessToken := jwt.NewWithClaims(accessMethod, accessClaims)
	accessToken.Header["kid"] = j.accessPrimaryKid
	accessTokenString, err := accessToken.SignedString(accessEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshEntry := j.refreshKeys[0]
	refreshMethod, err := signingMethodForKey(refreshEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("refresh key: %w", err)
	}
	refreshToken := jwt.NewWithClaims(refreshMethod, refreshClaims)
	refreshToken.Header["kid"] = j.refreshPrimaryKid
	refreshTokenString, err := refreshToken.SignedString(refreshEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:      accessTokenString,
		RefreshToken:     refreshTokenString,
		AccessExpiresAt:  accessExpiry.Unix(),
		RefreshExpiresAt: refreshExpiry.Unix(),
	}, nil
}

func buildValidMethodsFromKeys(keys []AsymmetricKeyEntry) []string {
	m := make(map[string]struct{})
	for _, k := range keys {
		method, err := signingMethodForKey(k.PrivateKey)
		if err != nil {
			continue
		}
		m[method.Alg()] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	return out
}

func (j *JWTServiceAsymmetric) rawValidateToken(ctx context.Context, tokenString, tokenType, primaryKid string, publicByKid map[string]crypto.PublicKey, validMethods []string, strict bool) (*CustomClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opts := []jwt.ParserOption{
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods(validMethods),
		jwt.WithExpirationRequired(),
	}
	if j.audience != "" {
		opts = append(opts, jwt.WithAudience(j.audience))
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if strict {
			k, ok := token.Header["kid"].(string)
			if !ok || k == "" {
				return nil, ErrMissingKidHeader
			}
		}
		kid := primaryKid
		if k, ok := token.Header["kid"].(string); ok && k != "" {
			kid = k
		}
		key, ok := publicByKid[kid]
		if !ok {
			return nil, ErrInvalidToken
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, ErrInvalidToken
			}
			return key, nil
		case *jwt.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, ErrInvalidToken
			}
			return key, nil
		case *jwt.SigningMethodEd25519:
			if _, ok := key.(ed25519.PublicKey); !ok {
				return nil, ErrInvalidToken
			}
			return key, nil
		default:
			return nil, ErrUnexpectedSigningMethod
		}
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, err)
	}
	if token == nil {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, ErrInvalidToken)
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, ErrInvalidToken)
	}
	if claims.TokenType != tokenType {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, ErrInvalidTokenType)
	}
	return claims, nil
}

func signingMethodForKey(priv crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	case *ecdsa.PrivateKey:
		if k.Curve == nil {
			return nil, errors.New("ECDSA private key requires non-nil Curve")
		}
		switch k.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256, nil
		case "P-384":
			return jwt.SigningMethodES384, nil
		case "P-521":
			return jwt.SigningMethodES512, nil
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %q", k.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T (supported: *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey)", priv)
	}
}
