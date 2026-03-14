package jwt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	revokedKeyPrefix     = "jwt:revoked:"
	userRevokedKeyPrefix = "jwt:user_revoked_at:"
)

var (
	// ErrEmptyJTI is returned by Revoke when jti is empty.
	ErrEmptyJTI = errors.New("jwt: jti is required for revocation")
	// ErrNoRedisClient is returned when the Redis client is nil.
	ErrNoRedisClient = errors.New("jwt: redis client is required")
)

// RevocationStore persists token and user-level revocation state. JWTService uses it to
// check blacklisted JTIs and user revocation timestamps (e.g. after password change).
type RevocationStore interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	RevokeUserTokens(ctx context.Context, userID uuid.UUID, ttl time.Duration) error
	IsUserRevoked(ctx context.Context, userID uuid.UUID, issuedAt int64) (bool, error)
}

// RedisRevocationStore implements RevocationStore using Redis. Keys use TTL; nil client returns ErrNoRedisClient.
type RedisRevocationStore struct {
	client *redis.Client
}

// NewRedisRevocationStore returns a revocation store backed by the given Redis client.
func NewRedisRevocationStore(client *redis.Client) *RedisRevocationStore {
	return &RedisRevocationStore{client: client}
}

// Revoke marks the given JTI as revoked for the specified TTL. TTL below 1s is treated as 7 days.
func (s *RedisRevocationStore) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" {
		return ErrEmptyJTI
	}
	if s == nil || s.client == nil {
		return ErrNoRedisClient
	}
	key := revokedKeyPrefix + jti
	if ttl < time.Second {
		ttl = time.Hour * 24 * 7
	}
	return s.client.Set(ctx, key, "1", ttl).Err()
}

// IsRevoked reports whether the JTI is currently revoked.
func (s *RedisRevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrNoRedisClient
	}
	if jti == "" {
		return false, nil
	}
	key := revokedKeyPrefix + jti
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("jwt revocation check: %w", err)
	}
	return n > 0, nil
}

// RevokeUserTokens stores a timestamp so that any token issued at or before that time is considered revoked. TTL below 1s is 7 days.
func (s *RedisRevocationStore) RevokeUserTokens(ctx context.Context, userID uuid.UUID, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return ErrNoRedisClient
	}
	if ttl < time.Second {
		ttl = time.Hour * 24 * 7
	}
	key := userRevokedKeyPrefix + userID.String()
	return s.client.Set(ctx, key, strconv.FormatInt(time.Now().Unix(), 10), ttl).Err()
}

// IsUserRevoked returns true if the token's issuedAt is at or before the user's revocation timestamp.
func (s *RedisRevocationStore) IsUserRevoked(ctx context.Context, userID uuid.UUID, issuedAt int64) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrNoRedisClient
	}
	key := userRevokedKeyPrefix + userID.String()
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("jwt user revocation check: %w", err)
	}
	revokedAt, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return false, fmt.Errorf("jwt user revocation parse: %w", err)
	}
	return issuedAt <= revokedAt, nil
}
