package jwtkit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisRevocationStore_Revoke_EmptyJTI_ReturnsError(t *testing.T) {
	t.Parallel()
	db, _ := redismock.NewClientMock()
	store := NewRedisRevocationStore(db)
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
	db, mock := redismock.NewClientMock()
	mock.ExpectSet("jwt:revoked:my-jti", "1", time.Hour).SetVal("OK")

	store := NewRedisRevocationStore(db)
	err := store.Revoke(context.Background(), "my-jti", time.Hour)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_Revoke_DefaultTTLWhenTTLTooSmall(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectSet("jwt:revoked:my-jti", "1", 7*24*time.Hour).SetVal("OK")

	store := NewRedisRevocationStore(db)
	err := store.Revoke(context.Background(), "my-jti", 0)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_Revoke_RedisError_ReturnsError(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectSet("jwt:revoked:err-jti", "1", time.Hour).SetErr(errors.New("redis down"))

	store := NewRedisRevocationStore(db)
	err := store.Revoke(context.Background(), "err-jti", time.Hour)
	require.Error(t, err)
}

func TestRedisRevocationStore_IsRevoked_NotRevoked_ReturnsFalse(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectExists("jwt:revoked:my-jti").SetVal(0)

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsRevoked(context.Background(), "my-jti")
	require.NoError(t, err)
	assert.False(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_IsRevoked_Revoked_ReturnsTrue(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectExists("jwt:revoked:my-jti").SetVal(1)

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsRevoked(context.Background(), "my-jti")
	require.NoError(t, err)
	assert.True(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
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
	db, _ := redismock.NewClientMock()
	store := NewRedisRevocationStore(db)
	revoked, err := store.IsRevoked(context.Background(), "")
	require.ErrorIs(t, err, ErrEmptyJTI)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_IsRevoked_RedisError_ReturnsError(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectExists("jwt:revoked:err-jti").SetErr(errors.New("redis down"))

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsRevoked(context.Background(), "err-jti")
	require.Error(t, err)
	assert.False(t, revoked)
}

func TestRedisRevocationStore_RevokeUserTokens_SetsKey(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	key := "jwt:user_revoked_at:" + userID.String()
	fixed := time.Unix(1700000000, 0)
	store := NewRedisRevocationStore(db)
	store.nowFunc = func() time.Time { return fixed }
	mock.ExpectEval(revokeUserTokensScript, []string{key}, "1700000000", 3600).SetVal("OK")

	err := store.RevokeUserTokens(context.Background(), userID, time.Hour)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
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
	db, mock := redismock.NewClientMock()
	key := "jwt:user_revoked_at:" + userID.String()
	fixed := time.Unix(1700000000, 0)
	store := NewRedisRevocationStore(db)
	store.nowFunc = func() time.Time { return fixed }
	mock.ExpectEval(revokeUserTokensScript, []string{key}, "1700000000", 604800).SetVal("OK")

	err := store.RevokeUserTokens(context.Background(), userID, 100*time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_IsUserRevoked_NoKey_ReturnsFalse(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	mock.ExpectGet("jwt:user_revoked_at:" + userID.String()).SetErr(redis.Nil)

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.NoError(t, err)
	assert.False(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_IsUserRevoked_ReturnsTrueWhenIssuedAtBeforeRevokedAt(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	mock.ExpectGet("jwt:user_revoked_at:" + userID.String()).SetVal("2000")

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.NoError(t, err)
	assert.True(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_IsUserRevoked_ReturnsFalseWhenIssuedAtAfterRevokedAt(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	mock.ExpectGet("jwt:user_revoked_at:" + userID.String()).SetVal("1000")

	store := NewRedisRevocationStore(db)
	revoked, err := store.IsUserRevoked(context.Background(), userID, 2000)
	require.NoError(t, err)
	assert.False(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
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
	db, mock := redismock.NewClientMock()
	key := "jwt:revoked:jti-first"
	mock.ExpectSetNX(key, "1", time.Hour).SetVal(true)

	store := NewRedisRevocationStore(db)
	first, err := store.RevokeIfFirst(context.Background(), "jti-first", time.Hour)
	require.NoError(t, err)
	assert.True(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_RevokeIfFirst_KeyExists_ReturnsFalse(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	key := "jwt:revoked:jti-exists"
	mock.ExpectSetNX(key, "1", time.Hour).SetVal(false)

	store := NewRedisRevocationStore(db)
	first, err := store.RevokeIfFirst(context.Background(), "jti-exists", time.Hour)
	require.NoError(t, err)
	assert.False(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_RevokeIfFirst_EmptyJTI(t *testing.T) {
	t.Parallel()
	db, _ := redismock.NewClientMock()
	store := NewRedisRevocationStore(db)
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
	db, mock := redismock.NewClientMock()
	mock.ExpectSetNX("jwt:revoked:jti-ttl", "1", 7*24*time.Hour).SetVal(true)
	store := NewRedisRevocationStore(db)
	first, err := store.RevokeIfFirst(context.Background(), "jti-ttl", 0)
	require.NoError(t, err)
	assert.True(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_RevokeIfFirst_RedisError(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	mock.ExpectSetNX("jwt:revoked:err-jti", "1", time.Hour).SetErr(errors.New("redis down"))
	store := NewRedisRevocationStore(db)
	_, err := store.RevokeIfFirst(context.Background(), "err-jti", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoke if first")
}

func TestWithRevocationKeyPrefix(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	store := NewRedisRevocationStore(db, WithRevocationKeyPrefix("myapp:"))
	mock.ExpectSet("myapp:jwt:revoked:jti-1", "1", time.Hour).SetVal("OK")
	err := store.Revoke(context.Background(), "jti-1", time.Hour)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWithRevocationKeyPrefix_IsRevoked(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	store := NewRedisRevocationStore(db, WithRevocationKeyPrefix("svc:"))
	mock.ExpectExists("svc:jwt:revoked:jti-1").SetVal(1)
	revoked, err := store.IsRevoked(context.Background(), "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWithRevocationNowFunc(t *testing.T) {
	t.Parallel()
	db, mock := redismock.NewClientMock()
	fixed := time.Unix(1700000000, 0)
	store := NewRedisRevocationStore(db, WithRevocationNowFunc(func() time.Time { return fixed }))
	userID := uuid.New()
	key := "jwt:user_revoked_at:" + userID.String()
	mock.ExpectEval(revokeUserTokensScript, []string{key}, "1700000000", 3600).SetVal("OK")
	err := store.RevokeUserTokens(context.Background(), userID, time.Hour)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_RevokeUserTokens_NilUUID(t *testing.T) {
	t.Parallel()
	db, _ := redismock.NewClientMock()
	store := NewRedisRevocationStore(db)
	err := store.RevokeUserTokens(context.Background(), uuid.Nil, time.Hour)
	require.ErrorIs(t, err, ErrNilUserID)
}

func TestRedisRevocationStore_RevokeUserTokens_RedisError(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	key := "jwt:user_revoked_at:" + userID.String()
	fixed := time.Unix(1700000000, 0)
	store := NewRedisRevocationStore(db, WithRevocationNowFunc(func() time.Time { return fixed }))
	mock.ExpectEval(revokeUserTokensScript, []string{key}, "1700000000", 3600).SetErr(errors.New("redis down"))
	err := store.RevokeUserTokens(context.Background(), userID, time.Hour)
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisRevocationStore_IsUserRevoked_ParseError(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	mock.ExpectGet("jwt:user_revoked_at:" + userID.String()).SetVal("not-a-number")
	store := NewRedisRevocationStore(db)
	_, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestRedisRevocationStore_IsUserRevoked_RedisError(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	db, mock := redismock.NewClientMock()
	mock.ExpectGet("jwt:user_revoked_at:" + userID.String()).SetErr(errors.New("redis down"))
	store := NewRedisRevocationStore(db)
	_, err := store.IsUserRevoked(context.Background(), userID, 1000)
	require.Error(t, err)
}
