package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AsymmetricKeyEntry holds a key id and a key pair for signing (private) and verification (public). Supported: *rsa.PrivateKey (RS256), *ecdsa.PrivateKey (ES256/ES384/ES512), ed25519.PrivateKey (EdDSA). RSA keys must be at least 2048 bits; ECDSA curves P-256, P-384, P-521.
type AsymmetricKeyEntry struct {
	Kid        string
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

// JWTServiceAsymmetric implements Service using RS256, ES256/ES384/ES512, or EdDSA. Use NewJWTServiceAsymmetric to construct.
type JWTServiceAsymmetric struct {
	accessKeys          []AsymmetricKeyEntry
	refreshKeys         []AsymmetricKeyEntry
	accessPrimaryKid    string
	refreshPrimaryKid   string
	accessTTL           time.Duration
	refreshTTL          time.Duration
	issuer              string
	audience            string
	revoker             RevocationStore
	userRoleLookup      atomic.Pointer[UserRoleLookup]
	accessPublicByKid   map[string]crypto.PublicKey
	refreshPublicByKid  map[string]crypto.PublicKey
	accessValidMethods  []string
	refreshValidMethods []string
	strictKid           atomic.Bool
}

// NewJWTServiceAsymmetric builds a JWT service with asymmetric keys. Issuer must be non-empty; access and refresh key slices must each contain at least one valid key pair. Revoker and userRoleLookup may be nil. Non-empty audience adds aud claim and validation. Key slices are copied but PrivateKey/PublicKey values are stored by reference; do not modify the key entries after construction.
func NewJWTServiceAsymmetric(
	accessKeys []AsymmetricKeyEntry,
	refreshKeys []AsymmetricKeyEntry,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
	revoker RevocationStore,
	userRoleLookup UserRoleLookup,
	audience string,
) (*JWTServiceAsymmetric, error) {
	if len(accessKeys) == 0 {
		return nil, fmt.Errorf("access keys must contain at least one key")
	}
	if len(refreshKeys) == 0 {
		return nil, fmt.Errorf("refresh keys must contain at least one key")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if accessTTL <= 0 {
		return nil, fmt.Errorf("accessTTL must be positive")
	}
	if refreshTTL <= 0 {
		return nil, fmt.Errorf("refreshTTL must be positive")
	}
	if accessTTL > MaxAccessTTL {
		return nil, fmt.Errorf("accessTTL must not exceed %v", MaxAccessTTL)
	}
	if refreshTTL > MaxRefreshTTL {
		return nil, fmt.Errorf("refreshTTL must not exceed %v", MaxRefreshTTL)
	}
	for i, k := range accessKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("access key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("access key %q: %w", k.Kid, err)
		}
	}
	for i, k := range refreshKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("refresh key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("refresh key %q: %w", k.Kid, err)
		}
	}
	accessPub := make(map[string]crypto.PublicKey, len(accessKeys))
	for _, k := range accessKeys {
		if k.Kid == "" {
			return nil, fmt.Errorf("access key Kid must be non-empty")
		}
		if _, exists := accessPub[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate access key Kid %q", k.Kid)
		}
		accessPub[k.Kid] = k.PublicKey
	}
	refreshPub := make(map[string]crypto.PublicKey, len(refreshKeys))
	for _, k := range refreshKeys {
		if k.Kid == "" {
			return nil, fmt.Errorf("refresh key Kid must be non-empty")
		}
		if _, exists := refreshPub[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate refresh key Kid %q", k.Kid)
		}
		refreshPub[k.Kid] = k.PublicKey
	}
	j := &JWTServiceAsymmetric{
		accessKeys:          slices.Clone(accessKeys),
		refreshKeys:         slices.Clone(refreshKeys),
		accessPrimaryKid:    accessKeys[0].Kid,
		refreshPrimaryKid:   refreshKeys[0].Kid,
		accessTTL:           accessTTL,
		refreshTTL:          refreshTTL,
		issuer:              issuer,
		audience:            audience,
		revoker:             revoker,
		accessPublicByKid:   accessPub,
		refreshPublicByKid:  refreshPub,
		accessValidMethods:  buildValidMethodsFromKeys(accessKeys),
		refreshValidMethods: buildValidMethodsFromKeys(refreshKeys),
	}
	if userRoleLookup != nil {
		j.userRoleLookup.Store(&userRoleLookup)
	}
	return j, nil
}

const minRSAKeyBits = 2048

func validateAsymmetricKeyPair(priv crypto.PrivateKey, pub crypto.PublicKey) error {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pubRSA, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA private key requires RSA public key")
		}
		if k.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("RSA key must be at least %d bits", minRSAKeyBits)
		}
		if err := k.Validate(); err != nil {
			return fmt.Errorf("RSA key validation: %w", err)
		}
		if k.N.Cmp(pubRSA.N) != 0 || k.E != pubRSA.E {
			return fmt.Errorf("RSA public key does not match private key")
		}
		return nil
	case ed25519.PrivateKey:
		pubEd, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("Ed25519 private key requires Ed25519 public key")
		}
		signer := priv.(crypto.Signer)
		if !bytes.Equal(signer.Public().(ed25519.PublicKey), pubEd) {
			return fmt.Errorf("Ed25519 public key does not match private key")
		}
		return nil
	case *ecdsa.PrivateKey:
		pubECDSA, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ECDSA private key requires ECDSA public key")
		}
		if k.Curve == nil {
			return fmt.Errorf("ECDSA private key requires non-nil Curve")
		}
		if k.Curve != pubECDSA.Curve || k.X.Cmp(pubECDSA.X) != 0 || k.Y.Cmp(pubECDSA.Y) != 0 {
			return fmt.Errorf("ECDSA public key does not match private key")
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

// SetUserRoleLookup sets or replaces the UserRoleLookup callback used during RefreshTokens. Safe for concurrent use.
func (j *JWTServiceAsymmetric) SetUserRoleLookup(fn UserRoleLookup) {
	j.userRoleLookup.Store(&fn)
}

// RevocationEnabled reports whether revocation is checked on ValidateAccessToken/ValidateRefreshToken (revoker is non-nil).
func (j *JWTServiceAsymmetric) RevocationEnabled() bool {
	return j.revoker != nil
}

// SetStrictKid when true rejects tokens that do not include a non-empty kid in the header (no fallback to primary key).
func (j *JWTServiceAsymmetric) SetStrictKid(strict bool) {
	j.strictKid.Store(strict)
}

// StrictKid returns whether tokens without kid header are rejected.
func (j *JWTServiceAsymmetric) StrictKid() bool {
	return j.strictKid.Load()
}

// GenerateTokenPair issues a new access and refresh token pair with unique JTIs and the given user id and role.
func (j *JWTServiceAsymmetric) GenerateTokenPair(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(j.accessTTL)
	refreshExpiry := now.Add(j.refreshTTL)
	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	accessReg := jwt.RegisteredClaims{
		ID:        accessJTI,
		ExpiresAt: jwt.NewNumericDate(accessExpiry),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    j.issuer,
	}
	if j.audience != "" {
		accessReg.Audience = jwt.ClaimStrings{j.audience}
	}
	accessClaims := &CustomClaims{
		UserID:           userID.String(),
		Role:             role,
		TokenType:        TokenTypeAccess,
		RegisteredClaims: accessReg,
	}
	refreshReg := jwt.RegisteredClaims{
		ID:        refreshJTI,
		ExpiresAt: jwt.NewNumericDate(refreshExpiry),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    j.issuer,
	}
	if j.audience != "" {
		refreshReg.Audience = jwt.ClaimStrings{j.audience}
	}
	refreshClaims := &CustomClaims{
		UserID:           userID.String(),
		Role:             role,
		TokenType:        TokenTypeRefresh,
		RegisteredClaims: refreshReg,
	}

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

// ValidateAccessToken parses the token and validates signature, issuer, audience (if set), token type, and revocation (if revoker is set).
func (j *JWTServiceAsymmetric) ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeAccess, j.accessPrimaryKid, j.accessPublicByKid, j.accessValidMethods)
}

// ValidateRefreshToken parses the token and validates signature, issuer, audience (if set), token type, and revocation (if revoker is set).
func (j *JWTServiceAsymmetric) ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeRefresh, j.refreshPrimaryKid, j.refreshPublicByKid, j.refreshValidMethods)
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

func (j *JWTServiceAsymmetric) validateToken(ctx context.Context, tokenString, tokenType, primaryKid string, publicByKid map[string]crypto.PublicKey, validMethods []string) (*CustomClaims, error) {
	opts := []jwt.ParserOption{
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods(validMethods),
		jwt.WithExpirationRequired(),
	}
	if j.audience != "" {
		opts = append(opts, jwt.WithAudience(j.audience))
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if j.strictKid.Load() {
			k, ok := token.Header["kid"].(string)
			if !ok || k == "" {
				return nil, fmt.Errorf("token missing kid header")
			}
		}
		kid := primaryKid
		if k, ok := token.Header["kid"].(string); ok && k != "" {
			kid = k
		}
		key, ok := publicByKid[kid]
		if !ok {
			return nil, fmt.Errorf("invalid token")
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("key type mismatch for RSA")
			}
			return key, nil
		case *jwt.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("key type mismatch for ECDSA")
			}
			return key, nil
		case *jwt.SigningMethodEd25519:
			if _, ok := key.(ed25519.PublicKey); !ok {
				return nil, fmt.Errorf("key type mismatch for EdDSA")
			}
			return key, nil
		default:
			return nil, fmt.Errorf("unexpected signing method")
		}
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, err)
	}
	if token == nil {
		return nil, fmt.Errorf("failed to validate %s token: invalid token", tokenType)
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.TokenType != tokenType {
		return nil, fmt.Errorf("invalid token type")
	}
	if err := j.checkRevocation(ctx, claims); err != nil {
		return nil, fmt.Errorf("jwt validate %s: %w", tokenType, err)
	}
	return claims, nil
}

func (j *JWTServiceAsymmetric) checkRevocation(ctx context.Context, claims *CustomClaims) error {
	return checkRevocationWithStore(ctx, claims, j.revoker)
}

// RevokeRefreshToken validates the refresh token then marks its JTI as revoked. TTL for the revocation key is until token expiry or refreshTTL. Returns ErrTokenInvalid when the token is expired, malformed, or invalid; ErrTokenCannotRevoke when the token has no JTI.
func (j *JWTServiceAsymmetric) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return ErrTokenInvalid
	}
	if claims.ID == "" {
		return ErrTokenCannotRevoke
	}
	if j.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := revocationTTL(claims, j.refreshTTL)
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAccessToken validates the access token then marks its JTI as revoked. Returns ErrTokenInvalid when the token is invalid.
func (j *JWTServiceAsymmetric) RevokeAccessToken(ctx context.Context, accessTokenString string) error {
	claims, err := j.ValidateAccessToken(ctx, accessTokenString)
	if err != nil {
		return ErrTokenInvalid
	}
	if claims.ID == "" {
		return ErrTokenCannotRevoke
	}
	if j.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := j.accessTTL
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			return nil
		}
	}
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAllForUser stores a user revocation timestamp so any token issued at or before that time is considered revoked.
func (j *JWTServiceAsymmetric) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if j.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := j.refreshTTL
	if j.accessTTL > ttl {
		ttl = j.accessTTL
	}
	return j.revoker.RevokeUserTokens(ctx, userID, ttl)
}

// RefreshTokens validates the refresh token, atomically revokes it (RevokeIfFirst), and issues a new token pair. Uses UserRoleLookup if set. Returns ErrRevokerRequired if revoker is nil.
func (j *JWTServiceAsymmetric) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	if j.revoker == nil {
		return nil, ErrRevokerRequired
	}
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}
	var fn *UserRoleLookup
	if loaded := j.userRoleLookup.Load(); loaded != nil && *loaded != nil {
		fn = loaded
	}
	return refreshTokensFromClaims(ctx, claims, j.revoker, j.refreshTTL, fn, j.GenerateTokenPair)
}

func signingMethodForKey(priv crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	case *ecdsa.PrivateKey:
		if k.Curve == nil {
			return nil, fmt.Errorf("ECDSA private key requires non-nil Curve")
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
