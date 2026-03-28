package jwtkit

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func buildTokenPairClaims(userID uuid.UUID, role, issuer, audience string, accessExpiry, refreshExpiry, now time.Time) (accessClaims, refreshClaims *CustomClaims) {
	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	accessReg := jwt.RegisteredClaims{
		ID:        accessJTI,
		ExpiresAt: jwt.NewNumericDate(accessExpiry),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    issuer,
	}
	if audience != "" {
		accessReg.Audience = jwt.ClaimStrings{audience}
	}
	accessClaims = &CustomClaims{
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
		Issuer:    issuer,
	}
	if audience != "" {
		refreshReg.Audience = jwt.ClaimStrings{audience}
	}
	refreshClaims = &CustomClaims{
		UserID:           userID.String(),
		Role:             role,
		TokenType:        TokenTypeRefresh,
		RegisteredClaims: refreshReg,
	}
	return accessClaims, refreshClaims
}

func revocationTTL(claims *CustomClaims, fallback time.Duration) time.Duration {
	if claims.ExpiresAt != nil {
		if d := time.Until(claims.ExpiresAt.Time); d > 0 {
			return d
		}
	}
	return fallback
}

func checkRevocationWithStore(ctx context.Context, claims *CustomClaims, revoker RevocationStore) error {
	if revoker == nil {
		return nil
	}
	if claims.ID == "" {
		return ErrTokenCannotRevoke
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id in claims: %w", err)
	}
	revoked, err := revoker.IsRevoked(ctx, claims.ID)
	if err != nil {
		return fmt.Errorf("revocation check: %w", err)
	}
	if revoked {
		return ErrTokenRevoked
	}
	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}
	userRevoked, err := revoker.IsUserRevoked(ctx, userID, issuedAt)
	if err != nil {
		return fmt.Errorf("user revocation check: %w", err)
	}
	if userRevoked {
		return ErrTokenRevoked
	}
	return nil
}

type tokenPairGenerator func(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error)

func refreshTokensFromClaims(
	ctx context.Context,
	claims *CustomClaims,
	revoker RevocationStore,
	refreshTTL time.Duration,
	userRoleLookup *UserRoleLookup,
	generatePair tokenPairGenerator,
) (*TokenPair, error) {
	if claims.ID == "" {
		return nil, ErrTokenCannotRevoke
	}
	ttl := revocationTTL(claims, refreshTTL)
	first, err := revoker.RevokeIfFirst(ctx, claims.ID, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}
	if !first {
		return nil, ErrRefreshTokenReplayed
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token claims: %w", err)
	}
	role := claims.Role
	if fn := userRoleLookup; fn != nil {
		freshRole, lookupErr := (*fn)(ctx, userID)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to lookup user role during refresh: %w", lookupErr)
		}
		role = freshRole
	}
	return generatePair(ctx, userID, role)
}
