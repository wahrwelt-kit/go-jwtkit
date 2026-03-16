// Package jwt provides JWT issuance, validation, and revocation for access/refresh token pairs.
//
// # HS256 (symmetric)
//
// Use NewJWTService with KeyEntry secrets. Issuer and TTLs are required; all secrets must be at least MinSecretLength (32) bytes.
// Key rotation is supported via kid (first key is primary). Optional RevocationStore (e.g. RedisRevocationStore) for revocation and refresh replay protection. UserRoleLookup can refresh role when issuing new tokens from a refresh token. If audience is non-empty, tokens include and validate the aud claim.
//
// # RS256 / EdDSA (asymmetric)
//
// Use NewJWTServiceAsymmetric with AsymmetricKeyEntry key pairs. Supports RSA (RS256, min 2048 bits), ECDSA (ES256/ES384/ES512 for P-256/P-384/P-521), and Ed25519 (EdDSA). Same revocation and UserRoleLookup semantics as HS256.
//
// # Revocation
//
// RevocationStore persists revoked JTIs and user revocation timestamps (e.g. after password change). RefreshTokens requires a non-nil store and uses RevokeIfFirst (atomic) to prevent refresh token replay. ErrRevokerRequired is returned when RefreshTokens is called without a revoker. RedisRevocationStore accepts WithRevocationKeyPrefix and WithRevocationNowFunc options.
//
// # HTTP integration
//
// JWTAuth middleware validates the Bearer token via ValidateAccessToken and stores claims in the request context; JWTAuthWithLogger(svc, errLog) uses ErrorLogger for validation errors. Use ClaimsIntoContext to set claims, ClaimsFromContext, UserIDFromContext, RoleFromContext to read them in handlers. ExtractRaw reads the token from the Authorization header (RFC 6750); ExtractRawFromCookie from a cookie.
//
// # Errors
//
// ErrTokenInvalid is returned by RevokeAccessToken and RevokeRefreshToken when the token fails validation. ErrTokenCannotRevoke when the token has no JTI. ErrRevokerRequired when RefreshTokens or revocation methods are called without a RevocationStore. ErrEmptyJTI and ErrNoRedisClient are from the revocation layer. Do not expose validation error messages to clients; use a generic message (e.g. "invalid token").
//
// # Redis revocation TTL
//
// RedisRevocationStore treats TTL below 1 second as 7 days to satisfy Redis key expiry constraints. Pass at least 1s for shorter revocation windows.
package jwt
