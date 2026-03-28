package jwtkit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccessSecret  = "access-secret-at-least-32-bytes!"
	testRefreshSecret = "refresh-secret-at-least-32-bytes!"
	testIssuer        = "test-issuer"
)

func newTestService(t *testing.T, revoker RevocationStore) *JWTService {
	t.Helper()
	svc, err := NewJWTService(Config{
		AccessKeys:     []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		RefreshKeys:    []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		AccessTTL:      time.Hour,
		RefreshTTL:     time.Hour,
		Issuer:         testIssuer,
		Revoker:        revoker,
		UserRoleLookup: nil,
		Audience:       "",
	})
	require.NoError(t, err)
	return svc
}

func TestJWTService_GenerateTokenPair_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Greater(t, pair.AccessExpiresAt, time.Now().Unix())
}

func TestJWTService_ValidateAccessToken_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	claims, err := service.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, TokenTypeAccess, claims.TokenType)
}

func TestJWTService_ValidateAccessToken_InvalidAudience(t *testing.T) {
	t.Parallel()
	keys := []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}}
	refreshKeys := []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}}
	svcA, err := NewJWTService(Config{AccessKeys: keys, RefreshKeys: refreshKeys, AccessTTL: time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer, Audience: "audience-a"})
	require.NoError(t, err)
	svcB, err := NewJWTService(Config{AccessKeys: keys, RefreshKeys: refreshKeys, AccessTTL: time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer, Audience: "audience-b"})
	require.NoError(t, err)
	userID := uuid.New()
	pair, err := svcA.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	claims, err := svcB.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateAccessToken_InvalidSignature(t *testing.T) {
	t.Parallel()
	service1, err := NewJWTService(Config{
		AccessKeys:  []KeyEntry{{Kid: "0", Secret: []byte("secret-1-at-least-32-bytes-long!")}},
		RefreshKeys: []KeyEntry{{Kid: "0", Secret: []byte("refresh-1-at-least-32-bytes-lon!")}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)
	service2, err := NewJWTService(Config{
		AccessKeys:  []KeyEntry{{Kid: "0", Secret: []byte("secret-2-at-least-32-bytes-long!")}},
		RefreshKeys: []KeyEntry{{Kid: "0", Secret: []byte("refresh-2-at-least-32-bytes-lon!")}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.NoError(t, err)
	userID := uuid.New()

	pair, err := service1.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	claims, err := service2.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateRefreshToken_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	claims, err := service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, TokenTypeRefresh, claims.TokenType)
}

func TestJWTService_ValidateAccessToken_RefreshTokenReturnsError(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	_, err = service.ValidateAccessToken(context.Background(), pair.RefreshToken)
	assert.Error(t, err)
}

func TestJWTService_ValidateRefreshToken_AccessTokenReturnsError(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	_, err = service.ValidateRefreshToken(context.Background(), pair.AccessToken)
	assert.Error(t, err)
}

func TestJWTService_RefreshTokens_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &memoryRevocationStore{})
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	newPair, err := service.RefreshTokens(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newPair.AccessToken)
	assert.NotEmpty(t, newPair.RefreshToken)
	assert.NotEqual(t, pair.AccessToken, newPair.AccessToken)
}

func TestJWTService_RefreshTokens_WithoutRevokerReturnsErr(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	_, err := service.RefreshTokens(context.Background(), "any")
	assert.ErrorIs(t, err, ErrRevokerRequired)
}

func TestJWTService_RefreshTokens_InvalidToken(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &memoryRevocationStore{})

	newPair, err := service.RefreshTokens(context.Background(), "invalid-token")
	require.Error(t, err)
	assert.Nil(t, newPair)
	assert.Contains(t, err.Error(), "validate refresh token")
}

func TestJWTService_NewJWTService_ShortSecret(t *testing.T) {
	t.Parallel()
	_, err := NewJWTService(Config{
		AccessKeys:  []KeyEntry{{Kid: "0", Secret: []byte("short")}},
		RefreshKeys: []KeyEntry{{Kid: "0", Secret: []byte("short")}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: testIssuer,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least")
}

func TestJWTService_NewJWTService_EmptyIssuer(t *testing.T) {
	t.Parallel()
	_, err := NewJWTService(Config{
		AccessKeys:  []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		RefreshKeys: []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestJWTService_RefreshTokens_RevokesOldToken(t *testing.T) {
	t.Parallel()
	revoker := &memoryRevocationStore{}
	service := newTestService(t, revoker)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	newPair, err := service.RefreshTokens(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newPair.RefreshToken)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestJWTService_RevokeRefreshToken_ThenValidateFails(t *testing.T) {
	t.Parallel()
	revoker := &memoryRevocationStore{}
	service := newTestService(t, revoker)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	err = service.RevokeRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestJWTService_RevokeAccessToken_Success(t *testing.T) {
	t.Parallel()
	revoker := &memoryRevocationStore{}
	service := newTestService(t, revoker)
	userID := uuid.New()
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	err = service.RevokeAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	_, err = service.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestJWTService_RevokeAllForUser_Success(t *testing.T) {
	t.Parallel()
	revoker := &memoryRevocationStore{}
	service := newTestService(t, revoker)
	userID := uuid.New()
	err := service.RevokeAllForUser(context.Background(), userID)
	require.NoError(t, err)
}

func TestJWTService_ValidateAccessToken_ExpiredTokenReturnsError(t *testing.T) {
	t.Parallel()
	svc, err := NewJWTService(Config{
		AccessKeys:     []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		RefreshKeys:    []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		AccessTTL:      1 * time.Millisecond,
		RefreshTTL:     time.Hour,
		Issuer:         testIssuer,
		Revoker:        nil,
		UserRoleLookup: nil,
		Audience:       "",
	})
	require.NoError(t, err)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)
	claims, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateRefreshToken_ExpiredTokenReturnsError(t *testing.T) {
	t.Parallel()
	svc, err := NewJWTService(Config{
		AccessKeys:     []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		RefreshKeys:    []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		AccessTTL:      time.Hour,
		RefreshTTL:     1 * time.Millisecond,
		Issuer:         testIssuer,
		Revoker:        nil,
		UserRoleLookup: nil,
		Audience:       "",
	})
	require.NoError(t, err)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)
	claims, err := svc.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_SetUserRoleLookup_RefreshUsesFreshRole(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &memoryRevocationStore{})
	userID := uuid.New()
	service.SetUserRoleLookup(func(_ context.Context, uid uuid.UUID) (string, error) {
		if uid != userID {
			return "", errors.New("wrong user")
		}
		return "admin", nil
	})
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	newPair, err := service.RefreshTokens(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	claims, err := service.ValidateAccessToken(context.Background(), newPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)
}
