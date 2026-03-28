package jwtkit

import (
	"net/http"
	"strings"
)

const maxTokenLength = 16 * 1024

// ExtractRaw returns the raw JWT string from the Authorization header (Bearer scheme per RFC 6750)
// Returns "" if the header is missing, not Bearer, r is nil, or the token exceeds maxTokenLength
// Scheme is case-insensitive; one or more spaces or tabs after "Bearer" are allowed
func ExtractRaw(r *http.Request) string {
	if r == nil {
		return ""
	}
	h := r.Header.Get("Authorization")
	if len(h) < 7 {
		return ""
	}
	if !strings.EqualFold(h[:6], "Bearer") {
		return ""
	}
	if h[6] != ' ' && h[6] != '\t' {
		return ""
	}
	rest := strings.TrimLeft(h[6:], " \t")
	if len(rest) == 0 {
		return ""
	}
	token := strings.TrimSpace(rest)
	if len(token) > maxTokenLength {
		return ""
	}
	return token
}

// ExtractRawFromCookie returns the value of the named cookie (trimmed of surrounding whitespace)
// Returns "" if the cookie is missing, r is nil, name is empty, the value is empty, or exceeds maxTokenLength
// Use when the client sends the JWT in a cookie instead of the Authorization header
func ExtractRawFromCookie(r *http.Request, name string) string {
	if r == nil || name == "" {
		return ""
	}
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	token := strings.TrimSpace(c.Value)
	if token == "" || len(token) > maxTokenLength {
		return ""
	}
	return token
}
