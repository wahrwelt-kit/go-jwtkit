package jwt_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	jwt "github.com/TakuyaYagam1/go-jwtkit"
	kitMock "github.com/TakuyaYagam1/go-jwtkit/mock"
)

type memoryRevocationStore struct {
	mu      sync.Mutex
	revoked map[string]struct{}
	userAt  map[uuid.UUID]int64
}

func (m *memoryRevocationStore) Revoke(_ context.Context, jti string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	m.revoked[jti] = struct{}{}
	return nil
}

func (m *memoryRevocationStore) RevokeIfFirst(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	if _, ok := m.revoked[jti]; ok {
		return false, nil
	}
	m.revoked[jti] = struct{}{}
	return true, nil
}

func (m *memoryRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[jti]
	return ok, nil
}

func (m *memoryRevocationStore) RevokeUserTokens(_ context.Context, userID uuid.UUID, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.userAt == nil {
		m.userAt = make(map[uuid.UUID]int64)
	}
	m.userAt[userID] = time.Now().Unix()
	return nil
}

func (m *memoryRevocationStore) IsUserRevoked(_ context.Context, userID uuid.UUID, issuedAt int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	revokedAt, ok := m.userAt[userID]
	if !ok {
		return false, nil
	}
	return issuedAt <= revokedAt, nil
}

const (
	testAccessSecret  = "access-secret-at-least-32-bytes!"
	testRefreshSecret = "refresh-secret-at-least-32-bytes!"
	testIssuer        = "test-issuer"
)

func newTestService(t *testing.T, revoker jwt.RevocationStore) *jwt.JWTService {
	t.Helper()
	svc, err := jwt.NewJWTService(
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		time.Hour, time.Hour, testIssuer, revoker, nil, "")
	require.NoError(t, err)
	return svc
}

func TestJWTService_GenerateTokenPair_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	assert.NoError(t, err)
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
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, jwt.TokenTypeAccess, claims.TokenType)
}

func TestJWTService_ValidateAccessToken_InvalidAudience(t *testing.T) {
	t.Parallel()
	keys := []jwt.KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}}
	refreshKeys := []jwt.KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}}
	svcA, err := jwt.NewJWTService(keys, refreshKeys, time.Hour, time.Hour, testIssuer, nil, nil, "audience-a")
	require.NoError(t, err)
	svcB, err := jwt.NewJWTService(keys, refreshKeys, time.Hour, time.Hour, testIssuer, nil, nil, "audience-b")
	require.NoError(t, err)
	userID := uuid.New()
	pair, err := svcA.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	claims, err := svcB.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateAccessToken_InvalidSignature(t *testing.T) {
	t.Parallel()
	service1, err := jwt.NewJWTService(
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("secret-1-at-least-32-bytes-long!")}},
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("refresh-1-at-least-32-bytes-lon!")}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	require.NoError(t, err)
	service2, err := jwt.NewJWTService(
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("secret-2-at-least-32-bytes-long!")}},
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("refresh-2-at-least-32-bytes-lon!")}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	require.NoError(t, err)
	userID := uuid.New()

	pair, err := service1.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	claims, err := service2.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateRefreshToken_Success(t *testing.T) {
	t.Parallel()
	service := newTestService(t, nil)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	claims, err := service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, jwt.TokenTypeRefresh, claims.TokenType)
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
	assert.ErrorIs(t, err, jwt.ErrRevokerRequired)
}

func TestJWTService_RefreshTokens_InvalidToken(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &memoryRevocationStore{})

	newPair, err := service.RefreshTokens(context.Background(), "invalid-token")
	assert.Error(t, err)
	assert.Nil(t, newPair)
	assert.Contains(t, err.Error(), "validate refresh token")
}

func TestJWTService_NewJWTService_ShortSecret(t *testing.T) {
	t.Parallel()
	_, err := jwt.NewJWTService(
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("short")}},
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte("short")}},
		time.Hour, time.Hour, testIssuer, nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least")
}

func TestJWTService_NewJWTService_EmptyIssuer(t *testing.T) {
	t.Parallel()
	_, err := jwt.NewJWTService(
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		[]jwt.KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		time.Hour, time.Hour, "", nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestJWTService_RefreshTokens_RevokesOldToken(t *testing.T) {
	t.Parallel()
	revoker := kitMock.NewMockRevocationStore(t)

	revoked := make(map[string]bool)
	revoker.EXPECT().
		RevokeIfFirst(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		RunAndReturn(func(_ context.Context, jti string, _ time.Duration) (bool, error) {
			revoked[jti] = true
			return true, nil
		})
	revoker.EXPECT().
		IsRevoked(mock.Anything, mock.AnythingOfType("string")).
		RunAndReturn(func(_ context.Context, jti string) (bool, error) {
			return revoked[jti], nil
		}).
		Maybe()
	revoker.EXPECT().
		IsUserRevoked(mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("int64")).
		Return(false, nil).
		Maybe()

	service := newTestService(t, revoker)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	claims, err := service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	oldJTI := claims.ID

	newPair, err := service.RefreshTokens(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newPair.RefreshToken)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	assert.True(t, revoked[oldJTI])
}

func TestJWTService_RevokeRefreshToken_ThenValidateFails(t *testing.T) {
	t.Parallel()
	revoker := kitMock.NewMockRevocationStore(t)

	revoked := make(map[string]bool)
	revoker.EXPECT().
		Revoke(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		RunAndReturn(func(_ context.Context, jti string, _ time.Duration) error {
			revoked[jti] = true
			return nil
		})
	revoker.EXPECT().
		IsRevoked(mock.Anything, mock.AnythingOfType("string")).
		RunAndReturn(func(_ context.Context, jti string) (bool, error) {
			return revoked[jti], nil
		}).
		Maybe()
	revoker.EXPECT().
		IsUserRevoked(mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("int64")).
		Return(false, nil).
		Maybe()

	service := newTestService(t, revoker)
	userID := uuid.New()

	pair, err := service.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	err = service.RevokeRefreshToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	_, err = service.ValidateRefreshToken(context.Background(), pair.RefreshToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestJWTService_RevokeAccessToken_Success(t *testing.T) {
	t.Parallel()
	revoker := kitMock.NewMockRevocationStore(t)
	var capturedJTI string
	revoker.EXPECT().
		IsRevoked(mock.Anything, mock.AnythingOfType("string")).
		Return(false, nil)
	revoker.EXPECT().
		IsUserRevoked(mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("int64")).
		Return(false, nil)
	revoker.EXPECT().
		Revoke(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		RunAndReturn(func(_ context.Context, jti string, _ time.Duration) error {
			capturedJTI = jti
			return nil
		})
	service := newTestService(t, revoker)
	userID := uuid.New()
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	err = service.RevokeAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.NotEmpty(t, capturedJTI)
}

func TestJWTService_RevokeAllForUser_Success(t *testing.T) {
	t.Parallel()
	revoker := kitMock.NewMockRevocationStore(t)
	revoker.EXPECT().
		RevokeUserTokens(mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("time.Duration")).
		Return(nil)
	service := newTestService(t, revoker)
	userID := uuid.New()
	err := service.RevokeAllForUser(context.Background(), userID)
	require.NoError(t, err)
}

func TestJWTService_SetUserRoleLookup_RefreshUsesFreshRole(t *testing.T) {
	t.Parallel()
	service := newTestService(t, &memoryRevocationStore{})
	userID := uuid.New()
	service.SetUserRoleLookup(func(ctx context.Context, uid uuid.UUID) (email, name, role string, err error) {
		if uid != userID {
			return "", "", "", errors.New("wrong user")
		}
		return "fresh@example.com", "Fresh Name", "admin", nil
	})
	pair, err := service.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	newPair, err := service.RefreshTokens(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	claims, err := service.ValidateAccessToken(context.Background(), newPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)
}
