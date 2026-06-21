package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/secret"
	"github.com/devSealWare/LightIPAM/internal/store"
)

func quietDispatcher(sealer *secret.Sealer) *Dispatcher {
	return NewDispatcher(nil, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestDispatcherSendSigned(t *testing.T) {
	sealer, err := secret.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	sealed, err := sealer.Seal("topsecret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var gotSig, gotEvent, gotCat, gotUA, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-LightIPAM-Signature")
		gotEvent = r.Header.Get("X-LightIPAM-Event")
		gotCat = r.Header.Get("X-LightIPAM-Category")
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d := quietDispatcher(sealer)
	event := Event{Type: "subnet.created", Category: CategoryIPAM, Instance: "light-ipam", Timestamp: time.Now().UTC()}
	body, _ := json.Marshal(event)
	result := d.send(context.Background(), store.Webhook{ID: "w1", URL: srv.URL, SecretSealed: sealed}, event, body)

	if result.Status != "success" || result.StatusCode != http.StatusAccepted {
		t.Fatalf("result = %+v", result)
	}
	if gotEvent != "subnet.created" || gotCat != "ipam" {
		t.Fatalf("event headers = %q/%q", gotEvent, gotCat)
	}
	if gotCT != "application/json" || gotUA != "LightIPAM-Webhook" {
		t.Fatalf("content-type/ua = %q/%q", gotCT, gotUA)
	}
	if want := "sha256=" + sign("topsecret", body); gotSig != want {
		t.Fatalf("signature = %q, want %q", gotSig, want)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body mismatch: got %s", gotBody)
	}
}

func TestDispatcherSendUnsignedAndErrors(t *testing.T) {
	var sawSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSig = r.Header.Get("X-LightIPAM-Signature")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := quietDispatcher(nil)
	event := Event{Type: "device.updated", Category: CategoryIPAM, Instance: "x", Timestamp: time.Now().UTC()}
	body, _ := json.Marshal(event)

	// No secret → no signature header, and a 5xx is recorded as failed.
	result := d.send(context.Background(), store.Webhook{ID: "w", URL: srv.URL}, event, body)
	if sawSig != "" {
		t.Fatalf("expected no signature header for an unsigned webhook, got %q", sawSig)
	}
	if result.Status != "failed" || result.StatusCode != http.StatusInternalServerError || result.Error == "" {
		t.Fatalf("expected a failed 5xx delivery, got %+v", result)
	}

	// An unreachable endpoint is a transport failure.
	bad := d.send(context.Background(), store.Webhook{ID: "w", URL: "http://127.0.0.1:0"}, event, body)
	if bad.Status != "failed" || bad.Error == "" {
		t.Fatalf("expected a transport failure, got %+v", bad)
	}
}

func TestCategoryForAction(t *testing.T) {
	cases := []struct {
		action   string
		category string
		ok       bool
	}{
		{"subnet.created", CategoryIPAM, true},
		{"subnet.updated", CategoryIPAM, true},
		{"address.bulk_state_set", CategoryIPAM, true},
		{"device.deleted", CategoryIPAM, true},
		{"mac.created", CategoryIPAM, true},
		{"scan.discovery.imported", CategoryDiscovery, true},
		{"scan.job.failed", CategoryScan, true},
		{"scan.schedule.updated", CategoryScan, true},
		{"scan.agent.approved", CategoryScan, true},
		{"settings.security.updated", CategorySecurity, true},
		{"user.role.updated", CategorySecurity, true},
		{"session.revoked_all", CategorySecurity, true},
		{"auth.login.locked", CategorySecurity, true},
		{"auth.mfa.failed", CategorySecurity, true},
		// Not delivered:
		{"subnet.csv_exported", "", false},
		{"address.csv_exported", "", false},
		{"auth.login", "", false},
		{"auth.logout", "", false},
		{"auth.mfa.success", "", false},
		{"policy.html", "", false},
		{"something.unknown", "", false},
	}
	for _, tc := range cases {
		cat, ok := categoryForAction(tc.action)
		if ok != tc.ok || cat != tc.category {
			t.Errorf("categoryForAction(%q) = (%q, %v), want (%q, %v)", tc.action, cat, ok, tc.category, tc.ok)
		}
	}
}

func TestMatches(t *testing.T) {
	if !matches(nil, CategoryIPAM) {
		t.Error("empty subscription should match any category")
	}
	if !matches([]string{}, CategoryScan) {
		t.Error("empty subscription should match any category")
	}
	if !matches([]string{CategoryIPAM, CategoryScan}, CategoryScan) {
		t.Error("expected match on a subscribed category")
	}
	if matches([]string{CategoryIPAM}, CategorySecurity) {
		t.Error("did not expect a match on an unsubscribed category")
	}
}

func TestSign(t *testing.T) {
	// Canonical HMAC-SHA256 test vector.
	got := sign("key", []byte("The quick brown fox jumps over the lazy dog"))
	want := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Fatalf("sign = %q, want %q", got, want)
	}
	if sign("key", []byte("a")) == sign("key2", []byte("a")) {
		t.Error("different keys must produce different signatures")
	}
}

func TestEventFromAudit(t *testing.T) {
	actor := "user-1"
	rec := store.AuditRecord{
		ActorUserID: &actor,
		Action:      "subnet.created",
		SubjectType: "subnet",
		SubjectID:   "sn-1",
		Metadata:    `{"cidr":"10.0.0.0/24"}`,
	}
	event, ok := EventFromAudit(rec, "light-ipam")
	if !ok {
		t.Fatal("expected a deliverable event")
	}
	if event.Type != "subnet.created" || event.Category != CategoryIPAM {
		t.Fatalf("unexpected event type/category: %+v", event)
	}
	if event.ActorUserID != "user-1" || event.SubjectID != "sn-1" || event.Instance != "light-ipam" {
		t.Fatalf("unexpected event fields: %+v", event)
	}
	if string(event.Metadata) != `{"cidr":"10.0.0.0/24"}` {
		t.Fatalf("metadata not carried: %s", event.Metadata)
	}
	// The payload must marshal to valid JSON with the metadata as a nested object.
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Event    string          `json:"event"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if decoded.Event != "subnet.created" {
		t.Fatalf("payload event = %q", decoded.Event)
	}

	// An invalid metadata string is dropped, not embedded raw.
	rec.Metadata = "not json"
	event, _ = EventFromAudit(rec, "light-ipam")
	if event.Metadata != nil {
		t.Fatalf("expected invalid metadata to be dropped, got %s", event.Metadata)
	}

	// A non-deliverable action reports ok=false.
	if _, ok := EventFromAudit(store.AuditRecord{Action: "auth.login"}, "x"); ok {
		t.Error("auth.login should not be deliverable")
	}
}
