package jwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwt "github.com/TakuyaYagam1/go-jwtkit"
)

func TestClaimsIntoContext_ClaimsFromContext(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)
	claims, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)

	ctx := context.Background()
	_, ok := jwt.ClaimsFromContext(ctx)
	assert.False(t, ok)

	ctx = jwt.ClaimsIntoContext(ctx, claims)
	c, ok := jwt.ClaimsFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, claims.UserID, c.UserID)
}

func TestUserIDFromContext(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "admin")
	require.NoError(t, err)
	claims, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)

	ctx := jwt.ClaimsIntoContext(context.Background(), claims)
	id, ok := jwt.UserIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, userID, id)

	_, ok = jwt.UserIDFromContext(context.Background())
	assert.False(t, ok)
}

func TestRoleFromContext(t *testing.T) {
	t.Parallel()
	ctx := jwt.ClaimsIntoContext(context.Background(), &jwt.CustomClaims{Role: "admin"})
	role, ok := jwt.RoleFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "admin", role)

	_, ok = jwt.RoleFromContext(context.Background())
	assert.False(t, ok)
}

func TestJWTAuth_Middleware(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)

	handler := jwt.JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := jwt.UserIDFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, userID, id)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestJWTAuth_NoToken_401(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	handler := jwt.JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestJWTAuth_InvalidToken_401(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	handler := jwt.JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
