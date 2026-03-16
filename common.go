package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func revocationTTL(claims *CustomClaims, fallback time.Duration) time.Duration {
	if claims.ExpiresAt != nil {
		if d := time.Until(claims.ExpiresAt.Time); d > 0 {
			return d
		}
	}
	return fallback
}

func checkRevocationWithStore(ctx context.Context, claims *CustomClaims, revoker RevocationStore) error {
	if claims.ID == "" {
		return fmt.Errorf("token missing jti claim")
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id in claims: %w", err)
	}
	if revoker == nil {
		return nil
	}
	revoked, err := revoker.IsRevoked(ctx, claims.ID)
	if err != nil {
		return fmt.Errorf("revocation check: %w", err)
	}
	if revoked {
		return fmt.Errorf("token revoked")
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
		return fmt.Errorf("token revoked")
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
		return nil, fmt.Errorf("refresh token missing jti claim")
	}
	ttl := revocationTTL(claims, refreshTTL)
	first, err := revoker.RevokeIfFirst(ctx, claims.ID, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}
	if !first {
		return nil, fmt.Errorf("refresh token already used")
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token claims: %w", err)
	}
	role := claims.Role
	if fn := userRoleLookup; fn != nil {
		_, _, freshRole, lookupErr := (*fn)(ctx, userID)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to lookup user role during refresh: %w", lookupErr)
		}
		role = freshRole
	}
	return generatePair(ctx, userID, role)
}
