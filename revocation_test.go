package jwt

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

func TestRedisRevocationStore_IsRevoked_EmptyJTI_ReturnsFalse(t *testing.T) {
	t.Parallel()
	db, _ := redismock.NewClientMock()
	store := NewRedisRevocationStore(db)
	revoked, err := store.IsRevoked(context.Background(), "")
	require.NoError(t, err)
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
	mock.Regexp().ExpectSet(key, `\d+`, time.Hour).SetVal("OK")

	store := NewRedisRevocationStore(db)
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
	mock.Regexp().ExpectSet(key, `\d+`, 7*24*time.Hour).SetVal("OK")

	store := NewRedisRevocationStore(db)
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
