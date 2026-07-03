package jwtkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func FuzzExtractRaw(f *testing.F) {
	for _, seed := range []string{
		"",
		"Bearer token",
		"bearer\t token ",
		"Basic dXNlcjpwYXNz",
		"Bearer " + strings.Repeat("a", maxTokenLength+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, authorization string) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", authorization)
		token := ExtractRaw(req)
		if len(token) > maxTokenLength {
			t.Fatalf("token length = %d, want <= %d", len(token), maxTokenLength)
		}
		if strings.TrimSpace(token) != token {
			t.Fatalf("token is not trimmed: %q", token)
		}
	})
}

func FuzzExtractRawFromCookie(f *testing.F) {
	for _, seed := range []string{
		"",
		testCookieToken,
		" token ",
		strings.Repeat("a", maxTokenLength+1),
		"a=b; c=d",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cookieValue string) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Cookie", "jwt="+cookieValue)
		token := ExtractRawFromCookie(req, "jwt")
		if len(token) > maxTokenLength {
			t.Fatalf("token length = %d, want <= %d", len(token), maxTokenLength)
		}
		if strings.TrimSpace(token) != token {
			t.Fatalf("token is not trimmed: %q", token)
		}
	})
}

func FuzzValidateAccessTokenMalformed(f *testing.F) {
	svc := newFuzzService(f)
	for _, seed := range []string{
		"",
		"not-a-token",
		"header.payload.signature",
		strings.Repeat("a", 4096),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tokenString string) {
		if len(tokenString) > maxTokenLength*2 {
			t.Skip()
		}
		_, _ = svc.ValidateAccessToken(context.Background(), tokenString)
	})
}

func FuzzValidateAccessTokenCustomClaims(f *testing.F) {
	svc := newFuzzService(f)
	validUserID := uuid.New().String()
	const fuzzJTI = "jti"
	for _, seed := range []struct {
		userID    string
		subject   string
		jti       string
		tokenType string
	}{
		{validUserID, validUserID, fuzzJTI, TokenTypeAccess},
		{"", validUserID, fuzzJTI, TokenTypeAccess},
		{validUserID, "", fuzzJTI, TokenTypeAccess},
		{uuid.Nil.String(), uuid.Nil.String(), fuzzJTI, TokenTypeAccess},
		{validUserID, validUserID, "", TokenTypeAccess},
		{validUserID, validUserID, fuzzJTI, TokenTypeRefresh},
	} {
		f.Add(seed.userID, seed.subject, seed.jti, seed.tokenType)
	}
	f.Fuzz(func(t *testing.T, userID, subject, jti, tokenType string) {
		if len(userID) > 512 || len(subject) > 512 || len(jti) > 512 || len(tokenType) > 128 {
			t.Skip()
		}
		now := time.Now().Add(-time.Second)
		claims := &CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        jti,
				Subject:   subject,
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				Issuer:    testIssuer,
			},
			UserID:    userID,
			TokenType: tokenType,
		}
		token := signFuzzAccessClaims(t, claims)
		got, err := svc.ValidateAccessToken(context.Background(), token)
		if err != nil {
			return
		}
		parsedUserID, parseErr := uuid.Parse(got.UserID)
		if parseErr != nil || parsedUserID == uuid.Nil {
			t.Fatalf("accepted invalid user_id %q", got.UserID)
		}
		if got.Subject != parsedUserID.String() {
			t.Fatalf("accepted subject %q for user_id %q", got.Subject, got.UserID)
		}
		if strings.TrimSpace(got.ID) == "" {
			t.Fatal("accepted empty jti")
		}
		if got.TokenType != TokenTypeAccess {
			t.Fatalf("accepted token_type %q", got.TokenType)
		}
	})
}

func newFuzzService(t testing.TB) *JWTService {
	t.Helper()
	svc, err := NewJWTService(Config{
		AccessKeys:  []KeyEntry{{Kid: "0", Secret: []byte(testAccessSecret)}},
		RefreshKeys: []KeyEntry{{Kid: "0", Secret: []byte(testRefreshSecret)}},
		AccessTTL:   time.Hour,
		RefreshTTL:  time.Hour,
		Issuer:      testIssuer,
		Leeway:      time.Second,
	})
	require.NoError(t, err)
	return svc
}

func signFuzzAccessClaims(t testing.TB, claims *CustomClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "0"
	tokenString, err := token.SignedString([]byte(testAccessSecret))
	require.NoError(t, err)
	return tokenString
}
