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
	benchInputBatch    = 256
)

func appendBenchTokenPairs(b *testing.B, svc *JWTService, ctx context.Context, pairs []*TokenPair) []*TokenPair {
	b.Helper()
	for range benchInputBatch {
		pair, err := svc.GenerateTokenPair(ctx, uuid.New(), "admin")
		if err != nil {
			b.Fatal(err)
		}
		pairs = append(pairs, pair)
	}
	return pairs
}

func appendBenchUserIDs(userIDs []uuid.UUID) []uuid.UUID {
	for range benchInputBatch {
		userIDs = append(userIDs, uuid.New())
	}
	return userIDs
}

func benchHS256Service(b *testing.B, revoker RevocationStore) *JWTService {
	b.Helper()
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GenerateTokenPair(ctx, userID, "admin"); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateAccessToken(ctx, token); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateRefreshToken(ctx, token); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateAccessToken(ctx, token); err != nil {
			b.Fatal(err)
		}
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
	pairs := appendBenchTokenPairs(b, svc, ctx, make([]*TokenPair, 0, benchInputBatch))
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if i == len(pairs) {
			b.StopTimer()
			pairs = appendBenchTokenPairs(b, svc, ctx, pairs)
			b.StartTimer()
		}
		if err := svc.RevokeRefreshToken(ctx, pairs[i].RefreshToken); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkJWTService_RevokeAccessToken(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	pairs := appendBenchTokenPairs(b, svc, ctx, make([]*TokenPair, 0, benchInputBatch))
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if i == len(pairs) {
			b.StopTimer()
			pairs = appendBenchTokenPairs(b, svc, ctx, pairs)
			b.StartTimer()
		}
		if err := svc.RevokeAccessToken(ctx, pairs[i].AccessToken); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkJWTService_RevokeAllForUser(b *testing.B) {
	revoker := &memoryRevocationStore{}
	svc := benchHS256Service(b, revoker)
	ctx := context.Background()
	userIDs := appendBenchUserIDs(make([]uuid.UUID, 0, benchInputBatch))
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if i == len(userIDs) {
			b.StopTimer()
			userIDs = appendBenchUserIDs(userIDs)
			b.StartTimer()
		}
		if err := svc.RevokeAllForUser(ctx, userIDs[i]); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func benchRS256Service(b *testing.B) *JWTServiceAsymmetric {
	b.Helper()
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GenerateTokenPair(ctx, userID, "admin"); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateAccessToken(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

func benchES256Service(b *testing.B) *JWTServiceAsymmetric {
	b.Helper()
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GenerateTokenPair(ctx, userID, "admin"); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateAccessToken(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

func benchEdDSAService(b *testing.B) *JWTServiceAsymmetric {
	b.Helper()
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GenerateTokenPair(ctx, userID, "admin"); err != nil {
			b.Fatal(err)
		}
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
	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.ValidateAccessToken(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}
