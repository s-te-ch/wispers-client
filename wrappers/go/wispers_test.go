package wispers

import (
	"testing"
)

func TestInMemoryStorageRestoreOrInit(t *testing.T) {
	storage := NewInMemoryStorage()
	defer storage.Close()

	node, state, err := storage.RestoreOrInit()
	if err != nil {
		t.Fatalf("RestoreOrInit failed: %v", err)
	}
	defer node.Close()

	if state != NodeStatePending {
		t.Fatalf("expected NodeStatePending, got %v", state)
	}

	if node.State() != NodeStatePending {
		t.Fatalf("expected node.State() == Pending, got %v", node.State())
	}
}

func TestInMemoryStorageReadRegistrationNotFound(t *testing.T) {
	storage := NewInMemoryStorage()
	defer storage.Close()

	_, err := storage.ReadRegistration()
	if err == nil {
		t.Fatal("expected error for unregistered storage")
	}

	wErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if wErr.Status != StatusNotFound {
		t.Fatalf("expected StatusNotFound, got %v", wErr.Status)
	}
}
