package jwtkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// MinSecretLength is the minimum byte length for HS256 KeyEntry.Secret
const (
	MinSecretLength  = 32                  // Minimum byte length for HS256 KeyEntry.Secret
	MaxAccessTTL     = 24 * time.Hour      // Maximum allowed access token TTL in Config
	MaxRefreshTTL    = 90 * 24 * time.Hour // Maximum allowed refresh token TTL in Config
	TokenTypeAccess  = "access"            // Value of token_type claim for access tokens
	TokenTypeRefresh = "refresh"           // Value of token_type claim for refresh tokens
	SigningMethod    = "HS256"             // Algorithm name for symmetric service
)

// UserRoleLookup returns the current role for a user
// Used during RefreshTokens to refresh claims before issuing a new token pair
// may be nil, in which case the role from the refresh token is reused
type UserRoleLookup func(ctx context.Context, userID uuid.UUID) (role string, err error)

// KeyEntry holds a key id (kid) and secret for HS256 signing
// Used for key rotation; the first key in the slice is the primary
// Secret can be zeroed after passing to NewJWTService to reduce exposure in memory
// Do not log or persist Secret in plain text
type KeyEntry struct {
	Kid    string // Key identifier; non-empty, unique per slice
	Secret []byte // At least MinSecretLength bytes; copied by NewJWTService
}

// Config configures NewJWTService
// Issuer is required; AccessKeys and RefreshKeys must each contain at least one key
// Revoker and UserRoleLookup may be nil; RefreshTokens requires a non-nil Revoker (returns ErrRevokerRequired)
// StrictKid when true rejects tokens without kid header; when false, missing kid falls back to the primary key
type Config struct {
	AccessKeys     []KeyEntry      // HS256 keys for access tokens; first is primary
	RefreshKeys    []KeyEntry      // HS256 keys for refresh tokens; first is primary
	AccessTTL      time.Duration   // Lifetime of access tokens; must be positive, ≤ MaxAccessTTL
	RefreshTTL     time.Duration   // Lifetime of refresh tokens; must be positive, ≤ MaxRefreshTTL
	Issuer         string          // Required; set in iss claim and validated on parse
	Audience       string          // Optional; if non-empty, aud claim is set and validated
	Revoker        RevocationStore // Optional; required for RefreshTokens and Revoke* methods
	UserRoleLookup UserRoleLookup  // Optional; called during RefreshTokens to refresh role
	StrictKid      bool            // If true, token must have kid header; no fallback to primary
}

// Service is the interface for JWT issuance, validation, refresh, and revocation
// Implemented by JWTService (HS256) and JWTServiceAsymmetric (RS256/ES256/EdDSA)
// All methods accept context.Context as first argument; cancellation is respected where applicable
type Service interface {
	// GenerateTokenPair issues a new access and refresh token pair for the user and role
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error)
	// ValidateAccessToken parses and validates the access token; checks revocation if RevocationStore is set
	ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	// ValidateRefreshToken parses and validates the refresh token; checks revocation if RevocationStore is set
	ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	// RefreshTokens validates the refresh token, revokes it (one-time use), and returns a new token pair
	RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error)
	// RevokeRefreshToken marks the refresh token as revoked (e.g. logout)
	RevokeRefreshToken(ctx context.Context, refreshTokenString string) error
	// RevokeAccessToken marks the access token as revoked
	RevokeAccessToken(ctx context.Context, accessTokenString string) error
	// RevokeAllForUser revokes all tokens for the user (e.g. logout everywhere, password change)
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// JWTService implements Service using HS256 symmetric signing
// Use NewJWTService to construct; do not instantiate manually
type JWTService struct {
	core

	accessKeysByKid   map[string][]byte
	refreshKeysByKid  map[string][]byte
	accessPrimaryKid  string
	refreshPrimaryKid string
	issuer            string
	audience          string
}

// CustomClaims extends jwt.RegisteredClaims with user_id, role, and token_type
// Used for both access and refresh tokens; token_type distinguishes them (TokenTypeAccess / TokenTypeRefresh)
// Email and full name are not stored in the token; use a /me or user API when the client needs them
type CustomClaims struct {
	UserID    string `json:"user_id"`        // UUID of the user
	Role      string `json:"role,omitempty"` // Role for authorization; optional
	TokenType string `json:"token_type"`     // TokenTypeAccess or TokenTypeRefresh
	jwt.RegisteredClaims
}

// TokenPair holds the access and refresh token strings and their Unix expiry timestamps
// Returned by GenerateTokenPair and RefreshTokens; send to the client for storage and Authorization header
type TokenPair struct {
	AccessToken      string `json:"access_token"`       // JWT string for access; send in Authorization: Bearer
	RefreshToken     string `json:"refresh_token"`      // JWT string for refresh; use only to call refresh endpoint
	AccessExpiresAt  int64  `json:"access_expires_at"`  // Unix seconds when access token expires
	RefreshExpiresAt int64  `json:"refresh_expires_at"` // Unix seconds when refresh token expires
}

// NewJWTService builds an HS256 JWT service from Config
// Issuer must be non-empty; AccessKeys and RefreshKeys must each contain at least one key
// All secrets must be at least MinSecretLength bytes; Kid must be non-empty and unique per slice
// Revoker and UserRoleLookup may be nil; RefreshTokens requires a non-nil Revoker (returns ErrRevokerRequired)
// Non-empty Audience adds aud claim and validates it on parse
// AccessTTL and RefreshTTL must be positive and not exceed MaxAccessTTL / MaxRefreshTTL
// The service copies secret bytes internally; the caller may zero KeyEntry.Secret slices after the call
func NewJWTService(cfg Config) (*JWTService, error) {
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
	accessByKid := make(map[string][]byte, len(cfg.AccessKeys))
	for _, k := range cfg.AccessKeys {
		if k.Kid == "" {
			return nil, errors.New("access key Kid must be non-empty")
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
	refreshByKid := make(map[string][]byte, len(cfg.RefreshKeys))
	for _, k := range cfg.RefreshKeys {
		if k.Kid == "" {
			return nil, errors.New("refresh key Kid must be non-empty")
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
		accessPrimaryKid:  cfg.AccessKeys[0].Kid,
		refreshPrimaryKid: cfg.RefreshKeys[0].Kid,
		issuer:            cfg.Issuer,
		audience:          cfg.Audience,
	}
	svc.core = *newCore(
		func(ctx context.Context, s string) (*CustomClaims, error) {
			return svc.rawValidateToken(ctx, s, TokenTypeAccess, svc.accessPrimaryKid, svc.accessKeysByKid, svc.StrictKid())
		},
		func(ctx context.Context, s string) (*CustomClaims, error) {
			return svc.rawValidateToken(ctx, s, TokenTypeRefresh, svc.refreshPrimaryKid, svc.refreshKeysByKid, svc.StrictKid())
		},
		svc.GenerateTokenPair,
		cfg.Revoker,
		cfg.UserRoleLookup,
		cfg.StrictKid,
		cfg.AccessTTL,
		cfg.RefreshTTL,
	)
	return svc, nil
}

// GenerateTokenPair issues a new access and refresh token pair with unique JTIs
// userID and role are stored in both tokens; use after login or registration
// Returns (*TokenPair, nil) or an error (e.g. if signing fails)
func (j *JWTService) GenerateTokenPair(_ context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(j.AccessTTL())
	refreshExpiry := now.Add(j.RefreshTTL())
	accessClaims, refreshClaims := buildTokenPairClaims(userID, role, j.issuer, j.audience, accessExpiry, refreshExpiry, now)

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

func (j *JWTService) rawValidateToken(ctx context.Context, tokenString, tokenType, primaryKid string, keysByKid map[string][]byte, strict bool) (*CustomClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
			return nil, ErrUnexpectedSigningMethod
		}
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
		key, ok := keysByKid[kid]
		if !ok {
			return nil, ErrInvalidToken
		}
		return key, nil
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
