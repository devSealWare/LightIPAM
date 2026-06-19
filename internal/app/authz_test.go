package app

import (
	"testing"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestCanWrite(t *testing.T) {
	if !canWrite(store.RoleAdmin) {
		t.Error("admin should be able to write")
	}
	if canWrite(store.RoleViewer) {
		t.Error("viewer should not be able to write")
	}
	if canWrite("") {
		t.Error("an unknown/empty role should not be able to write")
	}
}

func TestSafeMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if !safeMethod(m) {
			t.Errorf("%s should be a safe method", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if safeMethod(m) {
			t.Errorf("%s should not be a safe method", m)
		}
	}
}

func TestPublicWritePath(t *testing.T) {
	for _, p := range []string{"/login", "/logout", "/bootstrap"} {
		if !publicWritePath(p) {
			t.Errorf("%s should be a public write path", p)
		}
	}
	for _, p := range []string{"/subnets", "/settings/users", "/scans"} {
		if publicWritePath(p) {
			t.Errorf("%s should not be a public write path", p)
		}
	}
}

func TestIsAccountPath(t *testing.T) {
	for _, p := range []string{"/account", "/account/password", "/account/mfa/enroll"} {
		if !isAccountPath(p) {
			t.Errorf("%s should be an account path", p)
		}
	}
	for _, p := range []string{"/accounts", "/", "/settings"} {
		if isAccountPath(p) {
			t.Errorf("%s should not be an account path", p)
		}
	}
}
