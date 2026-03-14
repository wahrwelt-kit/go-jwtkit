# go-jwtkit

JWT for Go: access token (short-lived, for API auth) and refresh token (long-lived, for issuing new pairs). HS256, configurable issuer and TTLs, optional revocation store, key rotation via kid.

## Install

```bash
go get github.com/TakuyaYagam1/go-jwtkit
```

## Package

- **`jwt`** — Service interface and JWTService: two-token model (access + refresh). GenerateTokenPair issues both; ValidateAccessToken / ValidateRefreshToken; RefreshTokens validates refresh and returns new pair. RevokeRefreshToken, RevokeAccessToken, RevokeAllForUser. NewJWTService(accessKeys, refreshKeys, accessTTL, refreshTTL, issuer, revoker, userRoleLookup); revoker and userRoleLookup may be nil. KeyEntry (Kid, Secret); secrets at least MinSecretLength (32) bytes. RevocationStore; RedisRevocationStore(client). SetUserRoleLookup for fresh email/name/role on refresh. CustomClaims, TokenPair.

Requires **github.com/golang-jwt/jwt/v5**, **github.com/google/uuid**; **github.com/redis/go-redis/v9** optional for RedisRevocationStore.
