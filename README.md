# go-jwtkit

[![CI](https://github.com/takuya-go-kit/go-jwtkit/actions/workflows/ci.yml/badge.svg)](https://github.com/takuya-go-kit/go-jwtkit/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/takuya-go-kit/go-jwtkit.svg)](https://pkg.go.dev/github.com/takuya-go-kit/go-jwtkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/takuya-go-kit/go-jwtkit)](https://goreportcard.com/report/github.com/takuya-go-kit/go-jwtkit)

JWT issuance, validation, and revocation for access/refresh token pairs.

## Install

```bash
go get github.com/takuya-go-kit/go-jwtkit
```

```go
import "github.com/takuya-go-kit/go-jwtkit"
```

## Features

- **HS256** (symmetric): NewJWTService with KeyEntry secrets; key rotation via kid
- **RS256 / EdDSA** (asymmetric): NewJWTServiceAsymmetric with AsymmetricKeyEntry key pairs
- Access and refresh tokens with configurable TTLs and issuer
- **RevocationStore**: blacklist JTIs and user-level revocation (e.g. RedisRevocationStore)
- **UserRoleLookup**: refresh role when issuing new tokens from refresh token
- **HTTP**: JWTAuth middleware; ExtractRaw, ExtractRawFromCookie; ClaimsFromContext, UserIDFromContext, RoleFromContext

## Example

```go
svc, err := jwt.NewJWTService(jwt.Config{
    AccessKeys:     []jwt.KeyEntry{{Kid: "0", Secret: accessSecret}},
    RefreshKeys:    []jwt.KeyEntry{{Kid: "0", Secret: refreshSecret}},
    AccessTTL:      time.Hour,
    RefreshTTL:      24 * time.Hour,
    Issuer:         "my-app",
    Revoker:        redisRevoker,
    UserRoleLookup: userRoleLookup,
    Audience:       "",
})
pair, _ := svc.GenerateTokenPair(ctx, userID, "admin")

mux := http.NewServeMux()
mux.Handle("/api/", jwt.JWTAuth(svc)(apiHandler))
```

In handlers after JWTAuth:

```go
userID, ok := jwt.UserIDFromContext(r.Context())
claims, ok := jwt.ClaimsFromContext(r.Context())
```

## API

| Symbol | Description |
|--------|-------------|
| Service | Interface: GenerateTokenPair, ValidateAccessToken, ValidateRefreshToken, RefreshTokens, Revoke*, RevokeAllForUser |
| JWTService | HS256 implementation; NewJWTService(Config) |
| JWTServiceAsymmetric | RS256/ES256/ES384/ES512/EdDSA implementation; NewJWTServiceAsymmetric(AsymmetricConfig), AsymmetricKeyEntry |
| Config, AsymmetricConfig | Config structs for constructors |
| CustomClaims | UserID, Role, TokenType, RegisteredClaims |
| TokenPair | AccessToken, RefreshToken, AccessExpiresAt, RefreshExpiresAt |
| KeyEntry | Kid, Secret (symmetric) |
| RevocationStore | Revoke, IsRevoked, RevokeUserTokens, IsUserRevoked; RedisRevocationStore |
| JWTAuth(svc) | Returns func(http.Handler) http.Handler: Bearer validation, claims in context; 401 on failure, 500 if svc is nil |
| ExtractRaw(r), ExtractRawFromCookie(r, name) | Raw token from header or cookie |
| ClaimsIntoContext, ClaimsFromContext, UserIDFromContext, RoleFromContext | Context helpers |
