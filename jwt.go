package jwt

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// MinSecretLength is the minimum byte length required for signing secrets (HS256).
const MinSecretLength = 32

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	AccessMethod     = "HS256"
	RefreshMethod    = "HS256"
)

// UserRoleLookup returns current email, name, and role for a user; used when refreshing tokens.
type UserRoleLookup func(ctx context.Context, userID uuid.UUID) (email, name, role string, err error)

// KeyEntry holds a key id (kid) and secret for signing; used for key rotation.
type KeyEntry struct {
	Kid    string
	Secret string
}

// Service is the interface for JWT issuance, validation, refresh, and revocation.
type Service interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, email, name, role string) (*TokenPair, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error)
	RevokeRefreshToken(ctx context.Context, refreshTokenString string) error
	RevokeAccessToken(ctx context.Context, accessTokenString string) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// JWTService is the default implementation of Service.
type JWTService struct {
	accessKeysByKid   map[string][]byte
	refreshKeysByKid  map[string][]byte
	accessPrimaryKid  string
	refreshPrimaryKid string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	issuer            string
	revoker           RevocationStore
	userRoleLookup    atomic.Pointer[UserRoleLookup]
}

// CustomClaims extends RegisteredClaims with user id, email, name, role, and token type.
type CustomClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Role      string `json:"role,omitempty"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenPair holds access and refresh token strings and their expiry timestamps (Unix).
type TokenPair struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	RefreshExpiresAt int64  `json:"refresh_expires_at"`
}

// NewJWTService builds a JWT service. Issuer must be non-empty; all key secrets must be at least MinSecretLength bytes.
// Revoker and userRoleLookup may be nil.
func NewJWTService(
	accessKeys []KeyEntry,
	refreshKeys []KeyEntry,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
	revoker RevocationStore,
	userRoleLookup UserRoleLookup,
) (*JWTService, error) {
	if len(accessKeys) == 0 {
		return nil, fmt.Errorf("access keys must contain at least one key")
	}
	if len(refreshKeys) == 0 {
		return nil, fmt.Errorf("refresh keys must contain at least one key")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	accessByKid := make(map[string][]byte, len(accessKeys))
	for _, k := range accessKeys {
		if len(k.Secret) < MinSecretLength {
			return nil, fmt.Errorf("access key %q secret must be at least %d bytes", k.Kid, MinSecretLength)
		}
		accessByKid[k.Kid] = []byte(k.Secret)
	}
	refreshByKid := make(map[string][]byte, len(refreshKeys))
	for _, k := range refreshKeys {
		if len(k.Secret) < MinSecretLength {
			return nil, fmt.Errorf("refresh key %q secret must be at least %d bytes", k.Kid, MinSecretLength)
		}
		refreshByKid[k.Kid] = []byte(k.Secret)
	}
	svc := &JWTService{
		accessKeysByKid:   accessByKid,
		refreshKeysByKid:  refreshByKid,
		accessPrimaryKid:  accessKeys[0].Kid,
		refreshPrimaryKid: refreshKeys[0].Kid,
		accessTTL:         accessTTL,
		refreshTTL:        refreshTTL,
		issuer:            issuer,
		revoker:           revoker,
	}
	if userRoleLookup != nil {
		svc.userRoleLookup.Store(&userRoleLookup)
	}
	return svc, nil
}

// SetUserRoleLookup sets or replaces the callback used during RefreshTokens to resolve current user data.
func (j *JWTService) SetUserRoleLookup(fn UserRoleLookup) {
	j.userRoleLookup.Store(&fn)
}

// GenerateTokenPair issues a new access and refresh token pair for the given user and claims.
func (j *JWTService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email, name, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(j.accessTTL)
	refreshExpiry := now.Add(j.refreshTTL)

	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	accessClaims := &CustomClaims{
		UserID:    userID.String(),
		Email:     email,
		FullName:  name,
		Role:      role,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI,
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
		},
	}

	refreshClaims := &CustomClaims{
		UserID:    userID.String(),
		Email:     email,
		FullName:  name,
		Role:      role,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.GetSigningMethod(AccessMethod), accessClaims)
	accessToken.Header["kid"] = j.accessPrimaryKid
	accessKey := j.accessKeysByKid[j.accessPrimaryKid]
	accessTokenString, err := accessToken.SignedString(accessKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken := jwt.NewWithClaims(jwt.GetSigningMethod(RefreshMethod), refreshClaims)
	refreshToken.Header["kid"] = j.refreshPrimaryKid
	refreshKey := j.refreshKeysByKid[j.refreshPrimaryKid]
	refreshTokenString, err := refreshToken.SignedString(refreshKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:      accessTokenString,
		RefreshToken:     refreshTokenString,
		AccessExpiresAt:  accessExpiry.Unix(),
		RefreshExpiresAt: refreshExpiry.Unix(),
	}, nil
}

// ValidateAccessToken parses and validates an access token; checks signature, issuer, type, and revocation.
func (j *JWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeAccess, j.accessPrimaryKid, j.accessKeysByKid)
}

// ValidateRefreshToken parses and validates a refresh token; checks signature, issuer, type, and revocation.
func (j *JWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeRefresh, j.refreshPrimaryKid, j.refreshKeysByKid)
}

func (j *JWTService) validateToken(ctx context.Context, tokenString, tokenType, primaryKid string, keysByKid map[string][]byte) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid := primaryKid
		if k, ok := token.Header["kid"].(string); ok && k != "" {
			kid = k
		}
		key, ok := keysByKid[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key, nil
	}, jwt.WithIssuer(j.issuer))
	if err != nil {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.TokenType != tokenType {
		return nil, fmt.Errorf("invalid token type")
	}
	if err := j.checkRevocation(ctx, claims); err != nil {
		return nil, fmt.Errorf("jwt validate %s: %w", tokenType, err)
	}
	return claims, nil
}

func (j *JWTService) checkRevocation(ctx context.Context, claims *CustomClaims) error {
	if claims.ID == "" {
		return fmt.Errorf("token missing jti claim")
	}
	if j.revoker == nil {
		return nil
	}
	revoked, err := j.revoker.IsRevoked(ctx, claims.ID)
	if err != nil {
		return fmt.Errorf("revocation check: %w", err)
	}
	if revoked {
		return fmt.Errorf("token revoked")
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id in claims: %w", err)
	}
	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}
	userRevoked, err := j.revoker.IsUserRevoked(ctx, userID, issuedAt)
	if err != nil {
		return fmt.Errorf("user revocation check: %w", err)
	}
	if userRevoked {
		return fmt.Errorf("token revoked")
	}
	return nil
}

// RevokeRefreshToken invalidates the given refresh token via the revocation store.
func (j *JWTService) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return fmt.Errorf("jwt revoke: %w", err)
	}
	if claims.ID == "" {
		return nil
	}
	if j.revoker == nil {
		return nil
	}
	exp := claims.ExpiresAt
	var ttl time.Duration
	if exp != nil {
		ttl = time.Until(exp.Time)
	}
	if ttl <= 0 {
		ttl = j.refreshTTL
	}
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RefreshTokens validates the refresh token, revokes it, and issues a new token pair. Uses UserRoleLookup if set.
func (j *JWTService) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}
	if j.revoker != nil && claims.ID != "" {
		ttl := j.refreshTTL
		if claims.ExpiresAt != nil {
			ttl = time.Until(claims.ExpiresAt.Time)
			if ttl <= 0 {
				ttl = j.refreshTTL
			}
		}
		if err := j.revoker.Revoke(ctx, claims.ID, ttl); err != nil {
			return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
		}
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token claims: %w", err)
	}

	email, name, role := claims.Email, claims.FullName, claims.Role
	if fn := j.userRoleLookup.Load(); fn != nil {
		freshEmail, freshName, freshRole, lookupErr := (*fn)(ctx, userID)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to lookup user role during refresh: %w", lookupErr)
		}
		email, name, role = freshEmail, freshName, freshRole
	}

	return j.GenerateTokenPair(ctx, userID, email, name, role)
}

// RevokeAccessToken invalidates the given access token. Returns nil if the token is already invalid.
func (j *JWTService) RevokeAccessToken(ctx context.Context, accessTokenString string) error {
	claims, err := j.ValidateAccessToken(ctx, accessTokenString)
	if err != nil {
		return nil
	}
	if claims.ID == "" || j.revoker == nil {
		return nil
	}
	ttl := j.accessTTL
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			return nil
		}
	}
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAllForUser invalidates all tokens issued to the user (e.g. after password change).
func (j *JWTService) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if j.revoker == nil {
		return nil
	}
	ttl := j.refreshTTL
	if j.accessTTL > ttl {
		ttl = j.accessTTL
	}
	return j.revoker.RevokeUserTokens(ctx, userID, ttl)
}
