package jwtkit

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// core holds raw validate callbacks, revoker, user role lookup, TTLs, and strictKid. Created by newCore; not used directly by callers
type core struct {
	rawValidateAccess  func(context.Context, string) (*CustomClaims, error)
	rawValidateRefresh func(context.Context, string) (*CustomClaims, error)
	generatePair       func(context.Context, uuid.UUID, string) (*TokenPair, error)
	revoker            RevocationStore
	userRoleLookup     atomic.Pointer[UserRoleLookup]
	strictKid          atomic.Bool
	accessTTL          time.Duration
	refreshTTL         time.Duration
}

// newCore builds core from raw validate/generate callbacks and config. Used by NewJWTService and NewJWTServiceAsymmetric
func newCore(
	rawAccess, rawRefresh func(context.Context, string) (*CustomClaims, error),
	generatePair func(context.Context, uuid.UUID, string) (*TokenPair, error),
	revoker RevocationStore,
	userRoleLookup UserRoleLookup,
	strictKid bool,
	accessTTL, refreshTTL time.Duration,
) *core {
	c := &core{
		rawValidateAccess:  rawAccess,
		rawValidateRefresh: rawRefresh,
		generatePair:       generatePair,
		revoker:            revoker,
		accessTTL:          accessTTL,
		refreshTTL:         refreshTTL,
	}
	if userRoleLookup != nil {
		c.userRoleLookup.Store(&userRoleLookup)
	}
	c.strictKid.Store(strictKid)
	return c
}

// AccessTTL returns the access token TTL used when generating tokens
func (c *core) AccessTTL() time.Duration { return c.accessTTL }

// RefreshTTL returns the refresh token TTL used when generating tokens and for revocation TTL fallback
func (c *core) RefreshTTL() time.Duration { return c.refreshTTL }

// SetUserRoleLookup sets or replaces the UserRoleLookup callback used during RefreshTokens
// Safe for concurrent use; pass nil to clear
func (c *core) SetUserRoleLookup(fn UserRoleLookup) {
	c.userRoleLookup.Store(&fn)
}

// RevocationEnabled reports whether a RevocationStore is configured
// When true, ValidateAccessToken and ValidateRefreshToken check revocation; RefreshTokens and Revoke* require it
func (c *core) RevocationEnabled() bool {
	return c.revoker != nil
}

// SetStrictKid sets whether tokens without kid header are rejected
// When true, kid is required and there is no fallback to the primary key; when false, missing kid uses the primary key
func (c *core) SetStrictKid(strict bool) {
	c.strictKid.Store(strict)
}

// StrictKid returns whether tokens without kid header are rejected
func (c *core) StrictKid() bool {
	return c.strictKid.Load()
}

// ValidateAccessToken parses the token, validates signature and standard claims (exp, iss, aud, kid if strict),
// then checks revocation when RevocationStore is set
// Returns (*CustomClaims, nil) or an error (e.g. ErrInvalidToken, ErrTokenRevoked, ErrUnexpectedSigningMethod)
func (c *core) ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	claims, err := c.rawValidateAccess(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	if err := checkRevocationWithStore(ctx, claims, c.revoker); err != nil {
		return nil, fmt.Errorf("jwt validate access: %w", err)
	}
	return claims, nil
}

// ValidateRefreshToken parses the token, validates signature and claims, then checks revocation when RevocationStore is set
// Use for refresh endpoint before calling RefreshTokens; do not use for access-protected routes
// Returns (*CustomClaims, nil) or an error (e.g. ErrInvalidToken, ErrTokenRevoked, ErrInvalidTokenType)
func (c *core) ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	claims, err := c.rawValidateRefresh(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	if err := checkRevocationWithStore(ctx, claims, c.revoker); err != nil {
		return nil, fmt.Errorf("jwt validate refresh: %w", err)
	}
	return claims, nil
}

// GenerateTokenPair delegates to the underlying service's generate callback (issues access and refresh tokens)
// Called by both JWTService and JWTServiceAsymmetric with their respective signing logic
func (c *core) GenerateTokenPair(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	return c.generatePair(ctx, userID, role)
}

// RevokeRefreshToken validates the refresh token, then marks its JTI as revoked in the RevocationStore
// Use for logout or one-time invalidation of a refresh token
// Returns nil on success; ErrTokenInvalid if the token is invalid; ErrTokenCannotRevoke if jti is missing; ErrRevokerRequired if revoker is nil
func (c *core) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	claims, err := c.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return ErrTokenInvalid
	}
	if claims.ID == "" {
		return ErrTokenCannotRevoke
	}
	if c.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := revocationTTL(claims, c.refreshTTL)
	return c.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAccessToken validates the access token, then marks its JTI as revoked for the remainder of its TTL
// Use when you need to invalidate a single access token (e.g. security event)
// Returns nil on success; ErrTokenInvalid, ErrTokenCannotRevoke, or ErrRevokerRequired when applicable
func (c *core) RevokeAccessToken(ctx context.Context, accessTokenString string) error {
	claims, err := c.ValidateAccessToken(ctx, accessTokenString)
	if err != nil {
		return ErrTokenInvalid
	}
	if claims.ID == "" {
		return ErrTokenCannotRevoke
	}
	if c.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := c.accessTTL
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			return nil
		}
	}
	return c.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAllForUser stores a user revocation timestamp so that all tokens issued at or before that time
// are considered revoked on subsequent ValidateAccessToken/ValidateRefreshToken
// Use for "logout everywhere" or password change
// Returns nil on success; ErrRevokerRequired when revoker is nil
func (c *core) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if c.revoker == nil {
		return ErrRevokerRequired
	}
	ttl := max(c.accessTTL, c.refreshTTL)
	return c.revoker.RevokeUserTokens(ctx, userID, ttl)
}

// RefreshTokens validates the refresh token, atomically revokes it via RevokeIfFirst (one-time use),
// then issues a new token pair; if UserRoleLookup is set, the new role is fetched for the new tokens
// Caller should return the new TokenPair to the client and discard the old refresh token
// Returns (*TokenPair, nil) or an error (e.g. ErrRevokerRequired, ErrTokenInvalid, ErrRefreshTokenReplayed)
func (c *core) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	if c.revoker == nil {
		return nil, ErrRevokerRequired
	}
	claims, err := c.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}
	var fn *UserRoleLookup
	if loaded := c.userRoleLookup.Load(); loaded != nil && *loaded != nil {
		fn = loaded
	}
	return refreshTokensFromClaims(ctx, claims, c.revoker, c.refreshTTL, fn, c.generatePair)
}
