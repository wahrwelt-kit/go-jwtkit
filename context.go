package jwtkit

import (
	"context"
	"slices"

	"github.com/google/uuid"
)

type claimsContextKey struct{}

// ClaimsIntoContext stores the given claims in ctx under a package-private key
// Use after JWTAuth middleware or after a manual ValidateAccessToken so downstream handlers
// can read them via ClaimsFromContext, UserIDFromContext, or RoleFromContext
func ClaimsIntoContext(ctx context.Context, c *CustomClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, c)
}

// ClaimsFromContext returns a copy of the CustomClaims from ctx (set by JWTAuth or ClaimsIntoContext),
// or (nil, false) if not set or nil
// The returned copy is independent; mutating it does not affect other handlers reading from the same request context
func ClaimsFromContext(ctx context.Context) (*CustomClaims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*CustomClaims)
	if !ok || c == nil {
		return nil, false
	}
	cp := *c
	reg := cp.RegisteredClaims
	if reg.ExpiresAt != nil {
		v := *reg.ExpiresAt
		reg.ExpiresAt = &v
	}
	if reg.NotBefore != nil {
		v := *reg.NotBefore
		reg.NotBefore = &v
	}
	if reg.IssuedAt != nil {
		v := *reg.IssuedAt
		reg.IssuedAt = &v
	}
	if len(reg.Audience) > 0 {
		reg.Audience = slices.Clone(reg.Audience)
	}
	cp.RegisteredClaims = reg
	return &cp, true
}

// UserIDFromContext returns the user ID from claims in ctx as a UUID
// Returns (uuid.Nil, false) if claims are not set or UserID is not a valid UUID string
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok || c == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.UserID)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// RoleFromContext returns the role from claims in ctx (e.g. for authorization checks)
// Returns ("", false) if claims are not set or role is empty
func RoleFromContext(ctx context.Context) (string, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok || c == nil {
		return "", false
	}
	return c.Role, true
}
