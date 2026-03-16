package jwt

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrTokenInvalid is returned by RevokeAccessToken when the token is expired, malformed, or otherwise invalid.
var ErrTokenInvalid = errors.New("token already invalid or missing")

// ErrRevokerRequired is returned by RefreshTokens when the service has no RevocationStore (required to prevent refresh token replay).
var ErrRevokerRequired = errors.New("RefreshTokens requires a non-nil RevocationStore to prevent refresh token replay")

// ErrTokenCannotRevoke is returned by RevokeAccessToken when the token has no JTI (claims.ID); such tokens cannot be revoked individually.
var ErrTokenCannotRevoke = errors.New("token has no JTI and cannot be revoked")

const (
	MinSecretLength  = 32
	MaxAccessTTL     = 24 * time.Hour
	MaxRefreshTTL    = 90 * 24 * time.Hour
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	SigningMethod    = "HS256"
)

// UserRoleLookup returns current email, full name, and role for a user. Used during RefreshTokens to refresh claims; may be nil.
type UserRoleLookup func(ctx context.Context, userID uuid.UUID) (email, name, role string, err error)

// KeyEntry holds a key id (kid) and secret for HS256 signing. Used for key rotation; first key in the slice is primary. Secret can be zeroed after use to reduce exposure in memory. Do not log Secret.
type KeyEntry struct {
	Kid    string
	Secret []byte
}

// Service is the interface for JWT issuance, validation, refresh, and revocation. Implemented by JWTService and JWTServiceAsymmetric.
type Service interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error)
	RevokeRefreshToken(ctx context.Context, refreshTokenString string) error
	RevokeAccessToken(ctx context.Context, accessTokenString string) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// JWTService implements Service using HS256. Use NewJWTService to construct.
type JWTService struct {
	accessKeysByKid   map[string][]byte
	refreshKeysByKid  map[string][]byte
	accessPrimaryKid  string
	refreshPrimaryKid string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	issuer            string
	audience          string
	revoker           RevocationStore
	userRoleLookup    atomic.Pointer[UserRoleLookup]
	strictKid         atomic.Bool
}

// CustomClaims extends jwt.RegisteredClaims with user_id, role, and token_type. Used for both access and refresh tokens. Email and full name are not stored in the token; use a /me or user API when the client needs them.
type CustomClaims struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role,omitempty"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenPair holds the access and refresh token strings and their Unix expiry timestamps for the client.
type TokenPair struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	RefreshExpiresAt int64  `json:"refresh_expires_at"`
}

// NewJWTService builds an HS256 JWT service. Issuer must be non-empty; access and refresh key slices must each contain at least one key; all secrets at least MinSecretLength bytes; Kid non-empty and unique. userRoleLookup and revoker may be nil; RefreshTokens requires a non-nil revoker (returns ErrRevokerRequired otherwise). Non-empty audience adds aud claim and validation.
// The service copies secret bytes internally; the caller may zero KeyEntry.Secret slices after the call to reduce exposure in memory.
func NewJWTService(
	accessKeys []KeyEntry,
	refreshKeys []KeyEntry,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
	revoker RevocationStore,
	userRoleLookup UserRoleLookup,
	audience string,
) (*JWTService, error) {
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
	accessByKid := make(map[string][]byte, len(accessKeys))
	for _, k := range accessKeys {
		if k.Kid == "" {
			return nil, fmt.Errorf("access key Kid must be non-empty")
		}
		if len(k.Secret) < MinSecretLength {
			return nil, fmt.Errorf("access key %q secret must be at least %d bytes", k.Kid, MinSecretLength)
		}
		if _, exists := accessByKid[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate access key Kid %q", k.Kid)
		}
		dst := make([]byte, len(k.Secret))
		copy(dst, k.Secret)
		accessByKid[k.Kid] = dst
	}
	refreshByKid := make(map[string][]byte, len(refreshKeys))
	for _, k := range refreshKeys {
		if k.Kid == "" {
			return nil, fmt.Errorf("refresh key Kid must be non-empty")
		}
		if len(k.Secret) < MinSecretLength {
			return nil, fmt.Errorf("refresh key %q secret must be at least %d bytes", k.Kid, MinSecretLength)
		}
		if _, exists := refreshByKid[k.Kid]; exists {
			return nil, fmt.Errorf("duplicate refresh key Kid %q", k.Kid)
		}
		dst := make([]byte, len(k.Secret))
		copy(dst, k.Secret)
		refreshByKid[k.Kid] = dst
	}
	svc := &JWTService{
		accessKeysByKid:   accessByKid,
		refreshKeysByKid:  refreshByKid,
		accessPrimaryKid:  accessKeys[0].Kid,
		refreshPrimaryKid: refreshKeys[0].Kid,
		accessTTL:         accessTTL,
		refreshTTL:        refreshTTL,
		issuer:            issuer,
		audience:          audience,
		revoker:           revoker,
	}
	if userRoleLookup != nil {
		svc.userRoleLookup.Store(&userRoleLookup)
	}
	return svc, nil
}

// SetUserRoleLookup sets or replaces the UserRoleLookup callback used during RefreshTokens. Safe for concurrent use.
func (j *JWTService) SetUserRoleLookup(fn UserRoleLookup) {
	j.userRoleLookup.Store(&fn)
}

// SetStrictKid when true rejects tokens that do not include a non-empty kid in the header (no fallback to primary key).
func (j *JWTService) SetStrictKid(strict bool) {
	j.strictKid.Store(strict)
}

// StrictKid returns whether tokens without kid header are rejected.
func (j *JWTService) StrictKid() bool {
	return j.strictKid.Load()
}

// RevocationEnabled reports whether revocation is checked on ValidateAccessToken/ValidateRefreshToken (revoker is non-nil).
func (j *JWTService) RevocationEnabled() bool {
	return j.revoker != nil
}

// GenerateTokenPair issues a new access and refresh token pair with unique JTIs and the given user id and role.
func (j *JWTService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
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

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken.Header["kid"] = j.accessPrimaryKid
	accessKey := j.accessKeysByKid[j.accessPrimaryKid]
	accessTokenString, err := accessToken.SignedString(accessKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken.Header["kid"] = j.refreshPrimaryKid
	refreshKey := j.refreshKeysByKid[j.refreshPrimaryKid]
	refreshTokenString, err := refreshToken.SignedString(refreshKey)
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
func (j *JWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeAccess, j.accessPrimaryKid, j.accessKeysByKid)
}

// ValidateRefreshToken parses the token and validates signature, issuer, audience (if set), token type, and revocation (if revoker is set).
func (j *JWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeRefresh, j.refreshPrimaryKid, j.refreshKeysByKid)
}

func (j *JWTService) validateToken(ctx context.Context, tokenString, tokenType, primaryKid string, keysByKid map[string][]byte) (*CustomClaims, error) {
	opts := []jwt.ParserOption{
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	}
	if j.audience != "" {
		opts = append(opts, jwt.WithAudience(j.audience))
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
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
		key, ok := keysByKid[kid]
		if !ok {
			return nil, fmt.Errorf("invalid token")
		}
		return key, nil
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

func (j *JWTService) checkRevocation(ctx context.Context, claims *CustomClaims) error {
	return checkRevocationWithStore(ctx, claims, j.revoker)
}

// RevokeRefreshToken validates the refresh token then marks its JTI as revoked. Expired tokens are rejected before revocation. TTL for the revocation key is until token expiry (or refreshTTL if not set). Returns ErrTokenInvalid when the token is expired, malformed, or invalid; ErrTokenCannotRevoke when the token has no JTI.
func (j *JWTService) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
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

// RefreshTokens validates the refresh token, atomically revokes it (RevokeIfFirst) to prevent replay, and issues a new token pair. Uses UserRoleLookup if set to refresh email/name/role. Returns ErrRevokerRequired if revoker is nil.
func (j *JWTService) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
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

// RevokeAccessToken validates the access token then marks its JTI as revoked. Returns ErrTokenInvalid when the token is expired, malformed, or invalid; ErrTokenCannotRevoke when the token has no JTI; ErrRevokerRequired when revoker is nil.
func (j *JWTService) RevokeAccessToken(ctx context.Context, accessTokenString string) error {
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

// RevokeAllForUser stores a user revocation timestamp so that any token issued at or before that time is considered revoked. Use after password change or global logout.
func (j *JWTService) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if j.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := j.refreshTTL
	if j.accessTTL > ttl {
		ttl = j.accessTTL
	}
	return j.revoker.RevokeUserTokens(ctx, userID, ttl)
}
