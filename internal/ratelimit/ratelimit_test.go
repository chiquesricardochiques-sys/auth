package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := New(3, 50*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("tentativa %d deveria passar", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("4ª tentativa deveria ser bloqueada")
	}
	if !l.Allow("outra") {
		t.Fatal("outra chave não deveria ser afetada")
	}

	time.Sleep(60 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("depois da janela deveria liberar")
	}

	l.Reset("k")
	l.Cleanup()
}
