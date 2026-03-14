// Package jwt provides JWT issuance, validation, and revocation for access/refresh token pairs.
//
// It uses HS256, configurable issuer and TTLs, key rotation via kid, and an optional
// RevocationStore for token blacklisting (e.g. Redis). UserRoleLookup can refresh
// email/name/role when issuing new tokens from a refresh token.
//
// Create a service with NewJWTService; pass nil for revoker or userRoleLookup when not needed.
// Use RedisRevocationStore for Redis-backed revocation, or implement RevocationStore yourself.
package jwt
