# go-jwtkit

[![CI](https://github.com/wahrwelt-kit/go-jwtkit/actions/workflows/ci.yml/badge.svg)](https://github.com/wahrwelt-kit/go-jwtkit/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/wahrwelt-kit/go-jwtkit.svg)](https://pkg.go.dev/github.com/wahrwelt-kit/go-jwtkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/wahrwelt-kit/go-jwtkit)](https://goreportcard.com/report/github.com/wahrwelt-kit/go-jwtkit)

JWT issuance, validation, and revocation for access/refresh token pairs.

## Install

```bash
go get github.com/wahrwelt-kit/go-jwtkit
```

```go
import jwt "github.com/wahrwelt-kit/go-jwtkit"
```

## Features

- **HS256** (symmetric): NewJWTService with KeyEntry secrets; key rotation via kid
- **RS256 / ES256 / ES384 / ES512 / EdDSA** (asymmetric): NewJWTServiceAsymmetric with AsymmetricKeyEntry key pairs
- **JWK/JWKS** helpers for exporting and importing asymmetric public keys
- Access and refresh tokens with configurable TTLs and issuer
- Strict token claim validation: exp, nbf, iat, iss, aud, kid, sub, user_id, token_type, and jti
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
    Leeway:         30 * time.Second,
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

Export public keys for verification services:

```go
set, err := jwt.PublicJWKSetFromKeys(accessKeys)
if err != nil {
    return err
}
_ = json.NewEncoder(w).Encode(set)
```

Use go-httpkit error responses with JWTAuth:

```go
auth := jwt.JWTAuth(svc, jwt.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, _ error, status int) {
    if status == http.StatusUnauthorized {
        httputil.HandleError(w, r, httperr.ErrNotAuthenticated())
        return
    }
    httputil.RenderErrorWithCode(w, r, status, "auth middleware misconfigured", httperr.CodeInternalError)
}))
```

## API

| Symbol | Description |
|--------|-------------|
| Service | Interface: GenerateTokenPair, ValidateAccessToken, ValidateRefreshToken, RefreshTokens, Revoke*, RevokeAllForUser |
| JWTService | HS256 implementation; NewJWTService(Config) |
| JWTServiceAsymmetric | RS256/ES256/ES384/ES512/EdDSA implementation; NewJWTServiceAsymmetric(AsymmetricConfig), AsymmetricKeyEntry |
| Config, AsymmetricConfig | Config structs for constructors |
| CustomClaims | UserID, Role, TokenType, RegisteredClaims; sub equals user_id |
| TokenPair | AccessToken, RefreshToken, AccessExpiresAt, RefreshExpiresAt |
| KeyEntry | Kid, Secret (symmetric) |
| PublicJWK, PublicJWKSet | Public JSON Web Key and key-set structs |
| PublicJWKFromKey, PublicKeyFromJWK | Convert supported public keys to/from JWK |
| PublicJWKSetFromKeys, PublicKeysFromJWKSet | Export/import asymmetric public key sets keyed by kid |
| RevocationStore | Revoke, IsRevoked, RevokeUserTokens, IsUserRevoked; RedisRevocationStore |
| JWTAuth(svc) | Returns func(http.Handler) http.Handler: Bearer validation, claims in context; JSON {code,message} on 401/500 |
| ExtractRaw(r), ExtractRawFromCookie(r, name) | Raw token from header or cookie |
| ClaimsIntoContext, ClaimsFromContext, UserIDFromContext, RoleFromContext | Context helpers |

## Security Notes

- HS256 secrets must be at least 32 bytes and should come from a secret manager or KMS-backed config.
- Tokens without `kid` are rejected; generated tokens always set `kid` for key rotation.
- Generated tokens set `sub` to the same UUID as `user_id`; validation rejects mismatches.
- `GenerateTokenPair` rejects `uuid.Nil`; validation rejects empty JTI, invalid user IDs, and unknown token types.
- JWK helpers export public keys only; never expose private keys through JWKS endpoints.
- Refresh tokens are one-time-use when `RefreshTokens` is backed by a `RevocationStore`.
- Prefer `Authorization: Bearer` for APIs; cookie extraction is available when the application owns the cookie security policy.
- Client-facing auth errors stay generic. Use server logs and `errors.Is` on returned errors for diagnostics.

## Testing

```bash
make test
make test-race
make test-fuzz FUZZTIME=10s
```
