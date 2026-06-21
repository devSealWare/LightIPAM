// Package webhook delivers outbound change notifications (Phase 6, ADR 0022). It
// is an app-side feature only: the audit log is the change feed, and a registered
// endpoint receives an HMAC-signed JSON POST whenever a matching change is audited.
// It adds no privilege and holds no agent secrets — only the per-webhook signing
// secret, which is sealed at rest with the app encryption key.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devSealWare/LightIPAM/internal/secret"
	"github.com/devSealWare/LightIPAM/internal/store"
)

// Subscribable event categories. A webhook subscribes to a subset; an empty set
// means "all categories".
const (
	CategoryIPAM      = "ipam"
	CategoryDiscovery = "discovery"
	CategoryScan      = "scan"
	CategorySecurity  = "security"
)

// Categories lists the subscribable categories in display order.
func Categories() []string {
	return []string{CategoryIPAM, CategoryDiscovery, CategoryScan, CategorySecurity}
}

// ValidCategory reports whether c is a known subscribable category.
func ValidCategory(c string) bool {
	switch c {
	case CategoryIPAM, CategoryDiscovery, CategoryScan, CategorySecurity:
		return true
	}
	return false
}

// Event is a change fanned out to subscribed webhooks. The JSON form is the
// webhook payload.
type Event struct {
	Type        string          `json:"event"`
	Category    string          `json:"category"`
	SubjectType string          `json:"subject_type"`
	SubjectID   string          `json:"subject_id,omitempty"`
	ActorUserID string          `json:"actor_user_id,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Instance    string          `json:"instance"`
	Timestamp   time.Time       `json:"timestamp"`
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// categoryForAction maps an audit action to a webhook category. The boolean is
// false for actions that should not produce a webhook — read-only exports and
// routine/successful auth events (kept out of the change + security-alert feeds).
// Pure, so it is unit-tested directly.
func categoryForAction(action string) (string, bool) {
	switch {
	case strings.HasSuffix(action, ".csv_exported"):
		return "", false
	case hasPrefixAny(action, "subnet.", "address.", "device.", "mac."):
		return CategoryIPAM, true
	case strings.HasPrefix(action, "scan.discovery."):
		return CategoryDiscovery, true
	case hasPrefixAny(action, "scan.job.", "scan.schedule.", "scan.agent."):
		return CategoryScan, true
	case hasPrefixAny(action, "settings.", "user.", "session."):
		return CategorySecurity, true
	case strings.HasPrefix(action, "auth."):
		// Only the security-relevant auth events, not routine login/logout.
		switch action {
		case "auth.login.failed", "auth.login.locked", "auth.mfa.failed":
			return CategorySecurity, true
		}
		return "", false
	default:
		return "", false
	}
}

// EventFromAudit builds a webhook Event from an audit record, reporting whether
// the action maps to a deliverable category.
func EventFromAudit(rec store.AuditRecord, instance string) (Event, bool) {
	category, ok := categoryForAction(rec.Action)
	if !ok {
		return Event{}, false
	}
	event := Event{
		Type:        rec.Action,
		Category:    category,
		SubjectType: rec.SubjectType,
		SubjectID:   rec.SubjectID,
		Instance:    instance,
		Timestamp:   time.Now().UTC(),
	}
	if rec.ActorUserID != nil {
		event.ActorUserID = *rec.ActorUserID
	}
	if rec.Metadata != "" && json.Valid([]byte(rec.Metadata)) {
		event.Metadata = json.RawMessage(rec.Metadata)
	}
	return event, true
}

// matches reports whether a webhook subscribed to events should receive an event
// in category. An empty subscription means "all categories".
func matches(events []string, category string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == category {
			return true
		}
	}
	return false
}

// sign returns the lowercase-hex HMAC-SHA256 of body under secret.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Dispatcher fans audited changes out to subscribed webhook endpoints.
type Dispatcher struct {
	store    *store.Store
	sealer   *secret.Sealer
	client   *http.Client
	logger   *slog.Logger
	instance string
	active   int32 // atomic gate: number of enabled webhooks
}

// NewDispatcher builds a Dispatcher. sealer may be nil (unsigned deliveries only).
func NewDispatcher(st *store.Store, sealer *secret.Sealer, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		store:    st,
		sealer:   sealer,
		client:   &http.Client{Timeout: 10 * time.Second},
		logger:   logger,
		instance: "light-ipam",
	}
}

// Refresh recomputes the active-webhook gate. Call at startup and after any
// webhook create/update/delete so Active() stays accurate.
func (d *Dispatcher) Refresh(ctx context.Context) {
	n, err := d.store.CountEnabledWebhooks(ctx)
	if err != nil {
		d.logger.Error("count enabled webhooks", "error", err)
		return
	}
	atomic.StoreInt32(&d.active, int32(n))
}

// Active reports whether any webhook is enabled, so the audit hook can skip work
// entirely when none are configured.
func (d *Dispatcher) Active() bool {
	return atomic.LoadInt32(&d.active) > 0
}

// AuditHook returns a store.AuditHook that fans matching audited changes out to
// subscribed webhooks asynchronously. Cheap when no webhooks are active.
func (d *Dispatcher) AuditHook() store.AuditHook {
	return func(_ context.Context, rec store.AuditRecord) {
		if !d.Active() {
			return
		}
		event, ok := EventFromAudit(rec, d.instance)
		if !ok {
			return
		}
		d.deliverAsync(event)
	}
}

// deliverAsync fans an event out in its own goroutine with a fresh context, so it
// outlives the request that produced the audit entry and never blocks it.
func (d *Dispatcher) deliverAsync(event Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.deliver(ctx, event)
	}()
}

func (d *Dispatcher) deliver(ctx context.Context, event Event) {
	hooks, err := d.store.ListEnabledWebhooks(ctx)
	if err != nil {
		d.logger.Error("list enabled webhooks", "error", err)
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		d.logger.Error("marshal webhook event", "error", err)
		return
	}
	for _, wh := range hooks {
		if !matches(wh.Events, event.Category) {
			continue
		}
		result := d.send(ctx, wh, event, body)
		d.record(ctx, result)
	}
}

// send POSTs the payload to one webhook and returns the delivery result. It does
// not persist the result; the caller records it.
func (d *Dispatcher) send(ctx context.Context, wh store.Webhook, event Event, body []byte) store.WebhookDelivery {
	result := store.WebhookDelivery{WebhookID: wh.ID, EventType: event.Type, Status: "failed"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LightIPAM-Webhook")
	req.Header.Set("X-LightIPAM-Event", event.Type)
	req.Header.Set("X-LightIPAM-Category", event.Category)
	req.Header.Set("X-LightIPAM-Timestamp", event.Timestamp.UTC().Format(time.RFC3339))
	if wh.SecretSealed != "" && d.sealer != nil {
		if plain, err := d.sealer.Open(wh.SecretSealed); err == nil {
			req.Header.Set("X-LightIPAM-Signature", "sha256="+sign(plain, body))
		} else {
			d.logger.Error("open webhook secret", "webhook_id", wh.ID, "error", err)
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	result.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Status = "success"
	} else {
		result.Error = fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return result
}

func (d *Dispatcher) record(ctx context.Context, del store.WebhookDelivery) {
	if err := d.store.RecordWebhookDelivery(ctx, del); err != nil {
		d.logger.Error("record webhook delivery", "error", err)
	}
}

// TestDeliver sends a synchronous "webhook.test" ping to one webhook, records the
// attempt, and returns its result so the UI can show success or the failure
// reason inline.
func (d *Dispatcher) TestDeliver(ctx context.Context, webhookID string) (store.WebhookDelivery, error) {
	wh, err := d.store.GetWebhook(ctx, webhookID)
	if err != nil {
		return store.WebhookDelivery{}, err
	}
	event := Event{
		Type:        "webhook.test",
		Category:    "test",
		SubjectType: "webhook",
		SubjectID:   wh.ID,
		Instance:    d.instance,
		Timestamp:   time.Now().UTC(),
		Metadata:    json.RawMessage(`{"message":"Test delivery from Light IPAM."}`),
	}
	body, err := json.Marshal(event)
	if err != nil {
		return store.WebhookDelivery{}, err
	}
	result := d.send(ctx, wh, event, body)
	d.record(ctx, result)
	return result, nil
}
