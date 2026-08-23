package server

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/olivermarcusson/claustra/internal/config"
	"github.com/olivermarcusson/claustra/internal/store"
)

// TestCeremonyExpiryIsStorable guards the bug that made every ceremony fail:
// the library only fills SessionData.Expires while it enforces timeouts, and a
// zero there is written to webauthn_challenges as 0001-01-01, which
// ConsumeChallenge can never match.
func TestCeremonyExpiryIsStorable(t *testing.T) {
	wa, err := newWebAuthn(config.Config{RPID: "claustra.example", RPDisplayName: "Claustra", Issuer: "https://claustra.example"})
	if err != nil {
		t.Fatal(err)
	}
	user := store.WebAuthnUser{User: store.User{ID: uuid.New(), WebAuthnHandle: []byte("0123456789abcdef"), Status: "active", CreatedAt: time.Now().UTC()}}

	_, registration, err := wa.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	_, login, err := wa.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	for name, expires := range map[string]time.Time{"registration": registration.Expires, "login": login.Expires} {
		if expires.IsZero() {
			t.Fatalf("%s: session expiry is zero, so the stored challenge would be born expired", name)
		}
		if until := time.Until(expires); until <= 0 || until > ChallengeTTL+time.Minute {
			t.Fatalf("%s: expiry %s is not within the ceremony window", name, until)
		}
	}
}

func TestChallengeExpiryNeverZero(t *testing.T) {
	got := challengeExpiry(time.Time{})
	if got.IsZero() || !got.After(time.Now()) {
		t.Fatalf("zero session expiry became %s", got)
	}
	fixed := time.Now().UTC().Add(90 * time.Second)
	if challengeExpiry(fixed) != fixed {
		t.Fatal("a real expiry must be preserved")
	}
}
