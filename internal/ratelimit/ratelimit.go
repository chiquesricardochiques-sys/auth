// Package ratelimit implementa um limitador simples de janela fixa, em memória.
package ratelimit

import (
	"sync"
	"time"
)

type entry struct {
	count   int
	resetAt time.Time
}

type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*entry
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, hits: make(map[string]*entry)}
}

// Allow conta uma tentativa para a chave e informa se ainda está dentro do limite.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.hits) > 100_000 {
		l.cleanupLocked(now)
	}

	e, ok := l.hits[key]
	if !ok || now.After(e.resetAt) {
		l.hits[key] = &entry{count: 1, resetAt: now.Add(l.window)}
		return true
	}

	e.count++
	return e.count <= l.max
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

// Cleanup remove chaves expiradas (chamado pelo janitor).
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	l.cleanupLocked(time.Now())
	l.mu.Unlock()
}

func (l *Limiter) cleanupLocked(now time.Time) {
	for k, e := range l.hits {
		if now.After(e.resetAt) {
			delete(l.hits, k)
		}
	}
}
