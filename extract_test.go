package jwt_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	jwt "github.com/TakuyaYagam1/go-jwtkit"
)

func TestExtractRaw(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, jwt.ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer abc123")
	assert.Equal(t, "abc123", jwt.ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer  ")
	assert.Equal(t, "", jwt.ExtractRaw(req))
}

func TestExtractRawFromCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, jwt.ExtractRawFromCookie(r, "token"))
	r.AddCookie(&http.Cookie{Name: "token", Value: "abc"})
	assert.Equal(t, "abc", jwt.ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "  x  "})
	assert.Equal(t, "x", jwt.ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, jwt.ExtractRawFromCookie(r, "other"))
}
