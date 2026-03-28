package jwtkit

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

type memoryRevocationStore struct {
	mu      sync.Mutex
	revoked map[string]struct{}
	userAt  map[uuid.UUID]int64
}

func (m *memoryRevocationStore) revokeJTI(jti string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	m.revoked[jti] = struct{}{}
}

func (m *memoryRevocationStore) Revoke(_ context.Context, jti string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	m.revoked[jti] = struct{}{}
	return nil
}

func (m *memoryRevocationStore) RevokeIfFirst(_ context.Context, jti string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	if _, ok := m.revoked[jti]; ok {
		return false, nil
	}
	m.revoked[jti] = struct{}{}
	return true, nil
}

func (m *memoryRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[jti]
	return ok, nil
}

func (m *memoryRevocationStore) RevokeUserTokens(_ context.Context, userID uuid.UUID, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.userAt == nil {
		m.userAt = make(map[uuid.UUID]int64)
	}
	m.userAt[userID] = time.Now().Unix()
	return nil
}

func (m *memoryRevocationStore) IsUserRevoked(_ context.Context, userID uuid.UUID, issuedAt int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	revokedAt, ok := m.userAt[userID]
	if !ok {
		return false, nil
	}
	return issuedAt <= revokedAt, nil
}
