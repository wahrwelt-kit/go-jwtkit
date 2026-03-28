package jwtkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	benchAccessSecret  = "access-secret-at-least-32-bytes!"
	benchRefreshSecret = "refresh-secret-at-least-32-bytes!"
	benchIssuer        = "bench-issuer"
)

func benchHS256Service(b *testing.B, revoker RevocationStore) *JWTService {
	svc, err := NewJWTService(Config{
		AccessKeys:     []KeyEntry{{Kid: "0", Secret: []byte(benchAccessSecret)}},
		RefreshKeys:    []KeyEntry{{Kid: "0", Secret: []byte(benchRefreshSecret)}},
		AccessTTL:      time.Hour,
		RefreshTTL:     time.Hour,
		Issuer:         benchIssuer,
		Revoker:        revoker,
		UserRoleLookup: nil,
		Audience:       "",
	})
	if err != nil {
		b.Fatal(err)
	}
	return svc
}

func BenchmarkJWTService_GenerateTokenPair(b *testing.B) {
	svc := benchHS256Service(b, nil)
	ctx := context.Background()
	userID := uuid.New()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.GenerateTokenPair(ctx, userID, "admin")
	}
}

func BenchmarkJWTService_ValidateAccessToken(b *testing.B) {
	svc := benchHS256Service(b, nil)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.AccessToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateAccessToken(ctx, token)
	}
}

func BenchmarkJWTService_ValidateRefreshToken(b *testing.B) {
	svc := benchHS256Service(b, nil)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.RefreshToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateRefreshToken(ctx, token)
	}
}

func BenchmarkJWTService_ValidateAccessToken_WithRevocationCheck(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.AccessToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateAccessToken(ctx, token)
	}
}

func BenchmarkJWTService_RefreshTokens(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	refreshToken := pair.RefreshToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		newPair, err := svc.RefreshTokens(ctx, refreshToken)
		if err != nil {
			b.Fatal(err)
		}
		refreshToken = newPair.RefreshToken
	}
}

func BenchmarkJWTService_RevokeRefreshToken(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	pairs := make([]*TokenPair, b.N)
	for i := range b.N {
		pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
		if err != nil {
			b.Fatal(err)
		}
		pairs[i] = pair
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		_ = svc.RevokeRefreshToken(ctx, pairs[i].RefreshToken)
	}
}

func BenchmarkJWTService_RevokeAccessToken(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	pairs := make([]*TokenPair, b.N)
	for i := range b.N {
		pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
		if err != nil {
			b.Fatal(err)
		}
		pairs[i] = pair
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		_ = svc.RevokeAccessToken(ctx, pairs[i].AccessToken)
	}
}

func BenchmarkJWTService_RevokeAllForUser(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	userIDs := make([]uuid.UUID, b.N)
	for i := range b.N {
		userIDs[i] = uuid.New()
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		_ = svc.RevokeAllForUser(ctx, userIDs[i])
	}
}

func benchRS256Service(b *testing.B) *JWTServiceAsymmetric {
	accessPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	refreshPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: &accessPriv.PublicKey}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: &refreshPriv.PublicKey}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: benchIssuer,
	})
	if err != nil {
		b.Fatal(err)
	}
	return svc
}

func BenchmarkJWTServiceAsymmetric_RS256_GenerateTokenPair(b *testing.B) {
	svc := benchRS256Service(b)
	ctx := context.Background()
	userID := uuid.New()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.GenerateTokenPair(ctx, userID, "admin")
	}
}

func BenchmarkJWTServiceAsymmetric_RS256_ValidateAccessToken(b *testing.B) {
	svc := benchRS256Service(b)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.AccessToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateAccessToken(ctx, token)
	}
}

func benchES256Service(b *testing.B) *JWTServiceAsymmetric {
	accessPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	refreshPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: accessPriv, PublicKey: &accessPriv.PublicKey}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: &refreshPriv.PublicKey}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: benchIssuer,
	})
	if err != nil {
		b.Fatal(err)
	}
	return svc
}

func BenchmarkJWTServiceAsymmetric_ES256_GenerateTokenPair(b *testing.B) {
	svc := benchES256Service(b)
	ctx := context.Background()
	userID := uuid.New()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.GenerateTokenPair(ctx, userID, "admin")
	}
}

func BenchmarkJWTServiceAsymmetric_ES256_ValidateAccessToken(b *testing.B) {
	svc := benchES256Service(b)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.AccessToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateAccessToken(ctx, token)
	}
}

func benchEdDSAService(b *testing.B) *JWTServiceAsymmetric {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	refreshPub, refreshPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	svc, err := NewJWTServiceAsymmetric(AsymmetricConfig{
		AccessKeys:  []AsymmetricKeyEntry{{Kid: "a1", PrivateKey: priv, PublicKey: pub}},
		RefreshKeys: []AsymmetricKeyEntry{{Kid: "r1", PrivateKey: refreshPriv, PublicKey: refreshPub}},
		AccessTTL:   time.Hour, RefreshTTL: time.Hour, Issuer: benchIssuer,
	})
	if err != nil {
		b.Fatal(err)
	}
	return svc
}

func BenchmarkJWTServiceAsymmetric_EdDSA_GenerateTokenPair(b *testing.B) {
	svc := benchEdDSAService(b)
	ctx := context.Background()
	userID := uuid.New()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.GenerateTokenPair(ctx, userID, "admin")
	}
}

func BenchmarkJWTServiceAsymmetric_EdDSA_ValidateAccessToken(b *testing.B) {
	svc := benchEdDSAService(b)
	ctx := context.Background()
	pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
	if err != nil {
		b.Fatal(err)
	}
	token := pair.AccessToken
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = svc.ValidateAccessToken(ctx, token)
	}
}
