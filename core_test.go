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

func TestCore_ValidateAccessToken_ReturnsRawError(t *testing.T) {
	t.Parallel()
	errBad := errors.New("raw access error")
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, errBad },
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return nil, nil },
		nil, nil, false, time.Hour, time.Hour,
	)
	_, err := c.ValidateAccessToken(context.Background(), "token")
	require.Error(t, err)
	assert.ErrorIs(t, err, errBad)
}

func TestCore_ValidateAccessToken_ChecksRevocation(t *testing.T) {
	t.Parallel()
	revoker := &memoryRevocationStore{}
	claims := &CustomClaims{UserID: uuid.New().String(), TokenType: TokenTypeAccess}
	claims.ID = "jti-1"
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return claims, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return nil, nil },
		revoker, nil, false, time.Hour, time.Hour,
	)
	_, err := c.ValidateAccessToken(context.Background(), "token")
	require.NoError(t, err)
	revoker.revokeJTI("jti-1")
	_, err = c.ValidateAccessToken(context.Background(), "token")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestCore_ValidateRefreshToken_ReturnsRawError(t *testing.T) {
	t.Parallel()
	errBad := errors.New("raw refresh error")
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, errBad },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return nil, nil },
		nil, nil, false, time.Hour, time.Hour,
	)
	_, err := c.ValidateRefreshToken(context.Background(), "token")
	require.Error(t, err)
	assert.ErrorIs(t, err, errBad)
}

func TestCore_RevokeRefreshToken_WithoutRevokerReturnsErrRevokerRequired(t *testing.T) {
	t.Parallel()
	claims := &CustomClaims{UserID: uuid.New().String(), TokenType: TokenTypeRefresh}
	claims.ID = "jti-1"
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return claims, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return nil, nil },
		nil, nil, false, time.Hour, time.Hour,
	)
	err := c.RevokeRefreshToken(context.Background(), "token")
	assert.ErrorIs(t, err, ErrRevokerRequired)
}

func TestCore_RevokeAllForUser_WithoutRevokerReturnsErrRevokerRequired(t *testing.T) {
	t.Parallel()
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return nil, nil },
		nil, nil, false, time.Hour, time.Hour,
	)
	err := c.RevokeAllForUser(context.Background(), uuid.New())
	assert.ErrorIs(t, err, ErrRevokerRequired)
}

func TestCore_RefreshTokens_WithoutRevokerReturnsErrRevokerRequired(t *testing.T) {
	t.Parallel()
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return &TokenPair{}, nil },
		nil, nil, false, time.Hour, time.Hour,
	)
	_, err := c.RefreshTokens(context.Background(), "token")
	assert.ErrorIs(t, err, ErrRevokerRequired)
}

func TestCore_AccessTTL_RefreshTTL(t *testing.T) {
	t.Parallel()
	c := newCore(
		nil, nil, nil, nil, nil, false, 2*time.Hour, 24*time.Hour,
	)
	assert.Equal(t, 2*time.Hour, c.AccessTTL())
	assert.Equal(t, 24*time.Hour, c.RefreshTTL())
}

func TestCore_RevocationEnabled(t *testing.T) {
	t.Parallel()
	cNil := newCore(nil, nil, nil, nil, nil, false, time.Hour, time.Hour)
	assert.False(t, cNil.RevocationEnabled())
	revoker := &memoryRevocationStore{}
	cWith := newCore(nil, nil, nil, revoker, nil, false, time.Hour, time.Hour)
	assert.True(t, cWith.RevocationEnabled())
}

func TestCore_SetStrictKid_StrictKid(t *testing.T) {
	t.Parallel()
	c := newCore(nil, nil, nil, nil, nil, false, time.Hour, time.Hour)
	assert.False(t, c.StrictKid())
	c.SetStrictKid(true)
	assert.True(t, c.StrictKid())
	c.SetStrictKid(false)
	assert.False(t, c.StrictKid())
}

func TestCore_RefreshTokens_ReplayedToken_ReturnsErrRefreshTokenReplayed(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	revoker := &neverFirstRevoker{}
	claims := &CustomClaims{UserID: userID.String(), TokenType: TokenTypeRefresh}
	claims.ID = "jti-replay"
	c := newCore(
		func(_ context.Context, _ string) (*CustomClaims, error) { return nil, nil },
		func(_ context.Context, _ string) (*CustomClaims, error) { return claims, nil },
		func(_ context.Context, _ uuid.UUID, _ string) (*TokenPair, error) { return &TokenPair{}, nil },
		revoker, nil, false, time.Hour, time.Hour,
	)
	_, err := c.RefreshTokens(context.Background(), "token")
	assert.ErrorIs(t, err, ErrRefreshTokenReplayed)
}

// neverFirstRevoker simulates a lost RevokeIfFirst race (concurrent refresh replay)
type neverFirstRevoker struct{}

func (r *neverFirstRevoker) Revoke(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
func (r *neverFirstRevoker) RevokeIfFirst(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, nil
}
func (r *neverFirstRevoker) IsRevoked(_ context.Context, _ string) (bool, error) { return false, nil }
func (r *neverFirstRevoker) RevokeUserTokens(_ context.Context, _ uuid.UUID, _ time.Duration) error {
	return nil
}
func (r *neverFirstRevoker) IsUserRevoked(_ context.Context, _ uuid.UUID, _ int64) (bool, error) {
	return false, nil
}

func TestCore_GenerateTokenPair_DelegatesToCallback(t *testing.T) {
	t.Parallel()
	want := &TokenPair{AccessToken: "a", RefreshToken: "r", AccessExpiresAt: 1, RefreshExpiresAt: 2}
	c := newCore(
		nil, nil,
		func(_ context.Context, _ uuid.UUID, role string) (*TokenPair, error) {
			assert.Equal(t, "admin", role)
			return want, nil
		},
		nil, nil, false, time.Hour, time.Hour,
	)
	got, err := c.GenerateTokenPair(context.Background(), uuid.New(), "admin")
	require.NoError(t, err)
	assert.Same(t, want, got)
}
