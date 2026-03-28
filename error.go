package jwtkit

import "errors"

var (
	// ErrTokenInvalid is returned by RevokeAccessToken and RevokeRefreshToken when the token is
	// expired, malformed, or otherwise fails validation before revocation can be attempted
	ErrTokenInvalid = errors.New("token already invalid or missing")

	// ErrRevokerRequired is returned by RefreshTokens when the service has no RevocationStore (required to prevent refresh token replay)
	ErrRevokerRequired = errors.New("RefreshTokens requires a non-nil RevocationStore to prevent refresh token replay")

	// ErrTokenCannotRevoke is returned by RevokeAccessToken, RevokeRefreshToken, and RefreshTokens
	// when the token has no JTI (claims.ID); such tokens cannot be individually revoked or one-time-used
	ErrTokenCannotRevoke = errors.New("token has no JTI and cannot be revoked")

	// ErrInvalidTokenType is returned when the token's token_type claim does not match the expected type (access vs refresh)
	ErrInvalidTokenType = errors.New("invalid token type")

	// ErrUnexpectedSigningMethod is returned when the token's signing algorithm does not match the service's keys
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")

	// ErrMissingKidHeader is returned when StrictKid is true and the token has no kid header
	ErrMissingKidHeader = errors.New("token missing kid header")

	// ErrTokenRevoked is returned when the token has been revoked (JTI or user-level)
	ErrTokenRevoked = errors.New("token revoked")

	// ErrInvalidToken is returned when the token is malformed, has invalid signature, or unknown kid
	ErrInvalidToken = errors.New("invalid token")

	// ErrRefreshTokenReplayed is returned by RefreshTokens when the refresh token has already been used
	// (one-time-use replay protection via RevokeIfFirst lost the race - token reuse attempt)
	ErrRefreshTokenReplayed = errors.New("refresh token already used")

	// ErrNilUserID is returned by RevokeUserTokens when userID is uuid.Nil
	ErrNilUserID = errors.New("jwt: user id is required for RevokeUserTokens")
)
