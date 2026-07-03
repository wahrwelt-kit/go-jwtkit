package jwtkit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRedisRevocationTestStore(t *testing.T, opts ...RedisRevocationStoreOption) (*RedisRevocationStore, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:         server.Addr(),
		DialTimeout:  50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})
	return NewRedisRevocationStore(client, opts...), server
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRedisRevocationStore_Revoke_EmptyJTI_ReturnsError(t *testing.T) {
	t.Parallel()
	store := NewRedisRevocationStore(nil)
	err := store.Revoke(context.Background(), "", time.Hour)
	require.ErrorIs(t, err, ErrEmptyJTI)
}

func TestRedisRevocationStore_Revoke_NilClient_ReturnsError(t *testing.T) {
	t.Parallel()
	store := &RedisRevocationStore{client: nil}
	err := store.Revoke(context.Background(), "some-jti", time.Hour)
	require.ErrorIs(t, err, ErrNoRedisClient)
}

func TestRedisRevocationStore_Revoke_SetsKey(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)

	err := store.Revoke(context.Background(), "my-jti", time.Hour)
	require.NoError(t, err)

	value, err := server.Get("jwt:revoked:my-jti")
	require.NoError(t, err)
	assert.Equal(t, "1", value)
	assert.Equal(t, time.Hour, server.TTL("jwt:revoked:my-jti"))
}

func TestRedisRevocationStore_Revoke_DefaultTTLWhenTTLTooSmall(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)

	err := store.Revoke(context.Background(), "my-jti", 0)
	require.NoError(t, err)

	assert.Equal(t, 7*24*time.Hour, server.TTL("jwt:revoked:my-jti"))
}

func TestRedisRevocationStore_Revoke_RedisError_ReturnsError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	err := store.Revoke(canceledContext(), "err-jti", time.Hour)
	require.Error(t, err)
}

func TestRedisRevocationStore_IsRevoked_NotRevoked_ReturnsFalse(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)

	revoked, err := store.IsRevoked(context.Background(), "my-jti")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsRevoked_Revoked_ReturnsTrue(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)
	require.NoError(t, server.Set("jwt:revoked:my-jti", "1"))

	revoked, err := store.IsRevoked(context.Background(), "my-jti")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRedisRevocationStore_IsRevoked_NilClient_ReturnsError(t *testing.T) {
	t.Parallel()
	store := &RedisRevocationStore{client: nil}
	revoked, err := store.IsRevoked(context.Background(), "any-jti")
	require.ErrorIs(t, err, ErrNoRedisClient)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsRevoked_EmptyJTI_ReturnsError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	revoked, err := store.IsRevoked(context.Background(), "")
	require.ErrorIs(t, err, ErrEmptyJTI)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsRevoked_RedisError_ReturnsError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	revoked, err := store.IsRevoked(canceledContext(), "err-jti")
	require.Error(t, err)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_RevokeUserTokens_SetsKey(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	key := "jwt:user_revoked_at:" + userID.String()
	fixed := time.Unix(1700000000, 0)
	store, server := newRedisRevocationTestStore(t, WithRevocationNowFunc(func() time.Time { return fixed }))

	err := store.RevokeUserTokens(context.Background(), userID, time.Hour)
	require.NoError(t, err)

	value, err := server.Get(key)
	require.NoError(t, err)
	assert.Equal(t, "1700000000", value)
	assert.Equal(t, time.Hour, server.TTL(key))
}

func TestRedisRevocationStore_RevokeUserTokens_DoesNotMoveTimestampBackward(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	key := "jwt:user_revoked_at:" + userID.String()
	now := time.Unix(1700000000, 0)
	store, server := newRedisRevocationTestStore(t, WithRevocationNowFunc(func() time.Time { return now }))

	require.NoError(t, store.RevokeUserTokens(context.Background(), userID, time.Hour))
	now = now.Add(-time.Hour)
	require.NoError(t, store.RevokeUserTokens(context.Background(), userID, time.Hour))

	value, err := server.Get(key)
	require.NoError(t, err)
	assert.Equal(t, "1700000000", value)
}

func TestRedisRevocationStore_RevokeUserTokens_NilClient_ReturnsError(t *testing.T) {
	t.Parallel()
	store := &RedisRevocationStore{client: nil}
	err := store.RevokeUserTokens(context.Background(), uuid.New(), time.Hour)
	require.ErrorIs(t, err, ErrNoRedisClient)
}

func TestRedisRevocationStore_RevokeUserTokens_DefaultTTLWhenTTLTooSmall(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	key := "jwt:user_revoked_at:" + userID.String()
	fixed := time.Unix(1700000000, 0)
	store, server := newRedisRevocationTestStore(t, WithRevocationNowFunc(func() time.Time { return fixed }))

	err := store.RevokeUserTokens(context.Background(), userID, 100*time.Millisecond)
	require.NoError(t, err)

	assert.Equal(t, 7*24*time.Hour, server.TTL(key))
}

func TestRedisRevocationStore_IsUserRevoked_NoKey_ReturnsFalse(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)

	revoked, err := store.IsUserRevoked(context.Background(), uuid.New(), 1000)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsUserRevoked_ReturnsTrueWhenIssuedAtBeforeRevokedAt(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	store, server := newRedisRevocationTestStore(t)
	require.NoError(t, server.Set("jwt:user_revoked_at:"+userID.String(), "2000"))

	revoked, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRedisRevocationStore_IsUserRevoked_ReturnsFalseWhenIssuedAtAfterRevokedAt(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	store, server := newRedisRevocationTestStore(t)
	require.NoError(t, server.Set("jwt:user_revoked_at:"+userID.String(), "1000"))

	revoked, err := store.IsUserRevoked(context.Background(), userID, 2000)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsUserRevoked_NilClient_ReturnsError(t *testing.T) {
	t.Parallel()
	store := &RedisRevocationStore{client: nil}
	revoked, err := store.IsUserRevoked(context.Background(), uuid.New(), 1000)
	require.ErrorIs(t, err, ErrNoRedisClient)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_RevokeIfFirst_SetsKey_ReturnsTrue(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)

	first, err := store.RevokeIfFirst(context.Background(), "jti-first", time.Hour)
	require.NoError(t, err)
	assert.True(t, first)

	value, err := server.Get("jwt:revoked:jti-first")
	require.NoError(t, err)
	assert.Equal(t, "1", value)
	assert.Equal(t, time.Hour, server.TTL("jwt:revoked:jti-first"))
}

func TestRedisRevocationStore_RevokeIfFirst_KeyExists_ReturnsFalse(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)

	first, err := store.RevokeIfFirst(context.Background(), "jti-exists", time.Hour)
	require.NoError(t, err)
	assert.True(t, first)

	first, err = store.RevokeIfFirst(context.Background(), "jti-exists", time.Hour)
	require.NoError(t, err)
	assert.False(t, first)
}

func TestRedisRevocationStore_RevokeIfFirst_EmptyJTI(t *testing.T) {
	t.Parallel()
	store := NewRedisRevocationStore(nil)
	_, err := store.RevokeIfFirst(context.Background(), "", time.Hour)
	require.ErrorIs(t, err, ErrEmptyJTI)
}

func TestRedisRevocationStore_RevokeIfFirst_NilClient(t *testing.T) {
	t.Parallel()
	store := &RedisRevocationStore{client: nil}
	_, err := store.RevokeIfFirst(context.Background(), "jti", time.Hour)
	require.ErrorIs(t, err, ErrNoRedisClient)
}

func TestRedisRevocationStore_RevokeIfFirst_DefaultTTL(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)

	first, err := store.RevokeIfFirst(context.Background(), "jti-ttl", 0)
	require.NoError(t, err)
	assert.True(t, first)
	assert.Equal(t, 7*24*time.Hour, server.TTL("jwt:revoked:jti-ttl"))
}

func TestRedisRevocationStore_RevokeIfFirst_RedisError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	_, err := store.RevokeIfFirst(canceledContext(), "err-jti", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoke if first")
}

func TestWithRevocationKeyPrefix(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t, WithRevocationKeyPrefix("myapp:"))

	err := store.Revoke(context.Background(), "jti-1", time.Hour)
	require.NoError(t, err)
	assert.True(t, server.Exists("myapp:jwt:revoked:jti-1"))
}

func TestWithRevocationKeyPrefix_IsRevoked(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t, WithRevocationKeyPrefix("svc:"))
	require.NoError(t, server.Set("svc:jwt:revoked:jti-1", "1"))

	revoked, err := store.IsRevoked(context.Background(), "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestWithRevocationNowFunc(t *testing.T) {
	t.Parallel()
	fixed := time.Unix(1700000000, 0)
	store, server := newRedisRevocationTestStore(t, WithRevocationNowFunc(func() time.Time { return fixed }))
	userID := uuid.New()
	key := "jwt:user_revoked_at:" + userID.String()

	err := store.RevokeUserTokens(context.Background(), userID, time.Hour)
	require.NoError(t, err)

	value, err := server.Get(key)
	require.NoError(t, err)
	assert.Equal(t, "1700000000", value)
}

func TestRedisRevocationStore_RevokeUserTokens_NilUUID(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	err := store.RevokeUserTokens(context.Background(), uuid.Nil, time.Hour)
	require.ErrorIs(t, err, ErrNilUserID)
}

func TestRedisRevocationStore_RevokeUserTokens_RedisError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	err := store.RevokeUserTokens(canceledContext(), uuid.New(), time.Hour)
	require.Error(t, err)
}

func TestRedisRevocationStore_IsUserRevoked_ParseError(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	store, server := newRedisRevocationTestStore(t)
	require.NoError(t, server.Set("jwt:user_revoked_at:"+userID.String(), "not-a-number"))

	_, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestRedisRevocationStore_IsUserRevoked_RedisError(t *testing.T) {
	t.Parallel()
	store, _ := newRedisRevocationTestStore(t)
	_, err := store.IsUserRevoked(canceledContext(), uuid.New(), 1000)
	require.Error(t, err)
}

func TestRedisRevocationStore_CommandFailureAfterServerClose(t *testing.T) {
	t.Parallel()
	store, server := newRedisRevocationTestStore(t)
	server.Close()
	err := store.Revoke(context.Background(), "closed-jti", time.Hour)
	require.Error(t, err)
}
