package jwtkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	logmock "github.com/takuya-go-kit/go-logkit/mock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	_, ok := ClaimsFromContext(ctx)
	assert.False(t, ok)

	ctx = ClaimsIntoContext(ctx, claims)
	c, ok := ClaimsFromContext(ctx)
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

	ctx := ClaimsIntoContext(context.Background(), claims)
	id, ok := UserIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, userID, id)

	_, ok = UserIDFromContext(context.Background())
	assert.False(t, ok)
}

func TestRoleFromContext(t *testing.T) {
	t.Parallel()
	ctx := ClaimsIntoContext(context.Background(), &CustomClaims{Role: "admin"})
	role, ok := RoleFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "admin", role)

	_, ok = RoleFromContext(context.Background())
	assert.False(t, ok)
}

func TestJWTAuth_Middleware(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(context.Background(), userID, "user")
	require.NoError(t, err)

	handler := JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := UserIDFromContext(r.Context())
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
	handler := JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := JWTAuth(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestJWTAuth_NilService_500(t *testing.T) {
	t.Parallel()
	handler := JWTAuth(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestJWTAuth_WithLogger_NilService_500(t *testing.T) {
	t.Parallel()
	l := logmock.NewMockLogger(t)
	l.On("Error", "jwt: JWTAuth nil Service (misconfigured), returning 500").Return()
	handler := JWTAuth(nil, WithLogger(l))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	l.AssertCalled(t, "Error", "jwt: JWTAuth nil Service (misconfigured), returning 500")
}

func TestJWTAuth_WithErrorHandler_NilService(t *testing.T) {
	t.Parallel()
	var capturedStatus int
	handler := JWTAuth(nil, WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error, status int) {
		capturedStatus = status
		w.WriteHeader(status)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, capturedStatus)
}

func TestJWTAuth_WithErrorHandler_NoToken(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	var capturedStatus int
	handler := JWTAuth(svc, WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error, status int) {
		capturedStatus = status
		w.WriteHeader(status)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, capturedStatus)
}

func TestJWTAuth_WithErrorHandler_InvalidToken(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, nil)
	var capturedStatus int
	var capturedErr error
	handler := JWTAuth(svc, WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error, status int) {
		capturedStatus = status
		capturedErr = err
		w.WriteHeader(status)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, capturedStatus)
	assert.Error(t, capturedErr)
}
