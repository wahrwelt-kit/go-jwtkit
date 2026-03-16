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

const revokeUserTokensScript = `
local cur = redis.call('GET', KEYS[1])
local curNum = tonumber(cur)
if not cur or curNum == nil or tonumber(ARGV[1]) >= curNum then
  return redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
end
return 'OK'
`

var (
	// ErrEmptyJTI is returned by Revoke when jti is empty.
	ErrEmptyJTI = errors.New("jwt: jti is required for revocation")
	// ErrNoRedisClient is returned when the Redis client is nil.
	ErrNoRedisClient = errors.New("jwt: redis client is required")
)

// RevocationStore persists revoked JTIs and user revocation timestamps. Used for token blacklisting and refresh replay protection.
type RevocationStore interface {
	// Revoke marks the JTI as revoked for the given TTL.
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	// RevokeIfFirst marks the JTI as revoked only if not already revoked (atomic). Returns true if this call was the first. Used for refresh token one-time use.
	RevokeIfFirst(ctx context.Context, jti string, ttl time.Duration) (first bool, err error)
	// IsRevoked reports whether the JTI is currently revoked.
	IsRevoked(ctx context.Context, jti string) (bool, error)
	// RevokeUserTokens stores a timestamp so tokens issued at or before that time are considered revoked.
	RevokeUserTokens(ctx context.Context, userID uuid.UUID, ttl time.Duration) error
	// IsUserRevoked returns true if issuedAt is at or before the user's revocation timestamp.
	IsUserRevoked(ctx context.Context, userID uuid.UUID, issuedAt int64) (bool, error)
}

// RedisRevocationStore implements RevocationStore using Redis. Keys have TTL. Nil client causes methods to return ErrNoRedisClient.
type RedisRevocationStore struct {
	client    *redis.Client
	keyPrefix string
	nowFunc   func() time.Time
}

// RedisRevocationStoreOption configures RedisRevocationStore (e.g. key prefix, time source for tests).
type RedisRevocationStoreOption func(*RedisRevocationStore)

// WithRevocationKeyPrefix sets the prefix prepended to all keys (e.g. to isolate services sharing one Redis).
func WithRevocationKeyPrefix(prefix string) RedisRevocationStoreOption {
	return func(s *RedisRevocationStore) { s.keyPrefix = prefix }
}

// WithRevocationNowFunc sets the time source for user revocation timestamps (e.g. in tests). Do not modify after use.
func WithRevocationNowFunc(fn func() time.Time) RedisRevocationStoreOption {
	return func(s *RedisRevocationStore) { s.nowFunc = fn }
}

// NewRedisRevocationStore returns a revocation store backed by the given Redis client.
func NewRedisRevocationStore(client *redis.Client, opts ...RedisRevocationStoreOption) *RedisRevocationStore {
	s := &RedisRevocationStore{client: client}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Revoke marks the JTI as revoked for the specified TTL. Returns ErrEmptyJTI if jti is empty, ErrNoRedisClient if client is nil. TTL below 1s is clamped to 7 days (documented in package doc).
func (s *RedisRevocationStore) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" {
		return ErrEmptyJTI
	}
	if s == nil || s.client == nil {
		return ErrNoRedisClient
	}
	key := s.keyPrefix + revokedKeyPrefix + jti
	if ttl < time.Second {
		ttl = time.Hour * 24 * 7
	}
	return s.client.Set(ctx, key, "1", ttl).Err()
}

// RevokeIfFirst marks the JTI as revoked only if not already present (Redis SET NX). Returns true if this call was the first, false if already revoked. TTL below 1s is clamped to 7 days.
func (s *RedisRevocationStore) RevokeIfFirst(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if jti == "" {
		return false, ErrEmptyJTI
	}
	if s == nil || s.client == nil {
		return false, ErrNoRedisClient
	}
	key := s.keyPrefix + revokedKeyPrefix + jti
	if ttl < time.Second {
		ttl = time.Hour * 24 * 7
	}
	ok, err := s.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("jwt revoke if first: %w", err)
	}
	return ok, nil
}

// IsRevoked reports whether the JTI is currently in the store (revoked). Returns ErrNoRedisClient if client is nil, ErrEmptyJTI if jti is empty.
func (s *RedisRevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrNoRedisClient
	}
	if jti == "" {
		return false, ErrEmptyJTI
	}
	key := s.keyPrefix + revokedKeyPrefix + jti
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("jwt revocation check: %w", err)
	}
	return n > 0, nil
}

// RevokeUserTokens stores a revocation timestamp for the user (tokens with issuedAt <= that time are revoked). Only updates if the new timestamp is >= current (atomic Lua). TTL below 1s is clamped to 7 days. Returns error if userID is uuid.Nil.
func (s *RedisRevocationStore) RevokeUserTokens(ctx context.Context, userID uuid.UUID, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return ErrNoRedisClient
	}
	if userID == uuid.Nil {
		return fmt.Errorf("jwt: user id is required for RevokeUserTokens")
	}
	if ttl < time.Second {
		ttl = time.Hour * 24 * 7
	}
	key := s.keyPrefix + userRevokedKeyPrefix + userID.String()
	now := time.Now
	if s.nowFunc != nil {
		now = s.nowFunc
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	sec := int(ttl.Seconds())
	if sec < 1 {
		sec = 1
	}
	return s.client.Eval(ctx, revokeUserTokensScript, []string{key}, ts, sec).Err()
}

// IsUserRevoked returns true if issuedAt is at or before the user's stored revocation timestamp. Returns ErrNoRedisClient if client is nil.
func (s *RedisRevocationStore) IsUserRevoked(ctx context.Context, userID uuid.UUID, issuedAt int64) (bool, error) {
	if s == nil || s.client == nil {
		return false, ErrNoRedisClient
	}
	key := s.keyPrefix + userRevokedKeyPrefix + userID.String()
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
