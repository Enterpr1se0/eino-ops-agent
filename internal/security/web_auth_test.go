package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"eino-ops-agent/internal/store"
)

func TestWebAuthInitializeLoginLogoutAndReset(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	auth := NewWebAuth(st, time.Hour)
	if err := auth.Initialize(ctx, "short"); err == nil {
		t.Fatal("short bootstrap password was accepted")
	}
	if err := auth.Initialize(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Login(ctx, "incorrect password value"); err == nil {
		t.Fatal("incorrect password logged in")
	}
	token, session, err := auth.Login(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || session.CSRFToken == "" || session.ExpiresAt.Before(time.Now()) {
		t.Fatalf("invalid session: %#v", session)
	}
	if _, err := auth.Authenticate(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := auth.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate(ctx, token); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("logged-out token remained valid: %v", err)
	}
	if err := auth.ResetPassword(ctx, "replacement password 2026"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Login(ctx, "correct horse battery staple"); err == nil {
		t.Fatal("old password remained valid")
	}
	if _, _, err := auth.Login(ctx, "replacement password 2026"); err != nil {
		t.Fatal(err)
	}
}
