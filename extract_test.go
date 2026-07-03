package jwtkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testCookieToken = "token"

func TestExtractRaw(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	assert.Empty(t, ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer abc123")
	assert.Equal(t, "abc123", ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer  ")
	assert.Empty(t, ExtractRaw(req))
}

func TestExtractRaw_NilRequest(t *testing.T) {
	t.Parallel()
	assert.Empty(t, ExtractRaw(nil))
}

func TestExtractRaw_NonBearerScheme(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	assert.Empty(t, ExtractRaw(req))
}

func TestExtractRaw_BearerNoSpace(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearertoken")
	assert.Empty(t, ExtractRaw(req))
}

func TestExtractRaw_BearerTab(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer\ttoken123")
	assert.Equal(t, "token123", ExtractRaw(req))
}

func TestExtractRaw_OversizedToken(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", maxTokenLength+1))
	assert.Empty(t, ExtractRaw(req))
}

func TestExtractRaw_ShortHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bear")
	assert.Empty(t, ExtractRaw(req))
}

func TestExtractRawFromCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	assert.Empty(t, ExtractRawFromCookie(r, testCookieToken))
	r.AddCookie(&http.Cookie{Name: testCookieToken, Value: "abc"})
	assert.Equal(t, "abc", ExtractRawFromCookie(r, testCookieToken))
	r = httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.AddCookie(&http.Cookie{Name: testCookieToken, Value: "  x  "})
	assert.Equal(t, "x", ExtractRawFromCookie(r, testCookieToken))
	r = httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	assert.Empty(t, ExtractRawFromCookie(r, "other"))
}

func TestExtractRawFromCookie_NilRequest(t *testing.T) {
	t.Parallel()
	assert.Empty(t, ExtractRawFromCookie(nil, "token"))
}

func TestExtractRawFromCookie_EmptyName(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	assert.Empty(t, ExtractRawFromCookie(req, ""))
}

func TestExtractRawFromCookie_EmptyCookieValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: testCookieToken, Value: ""})
	assert.Empty(t, ExtractRawFromCookie(req, testCookieToken))
}

func TestExtractRawFromCookie_OversizedValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: testCookieToken, Value: strings.Repeat("a", maxTokenLength+1)})
	assert.Empty(t, ExtractRawFromCookie(req, testCookieToken))
}
