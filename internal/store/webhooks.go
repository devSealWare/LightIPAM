package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// Webhook is a registered outbound notification endpoint (Phase 6, ADR 0022).
type Webhook struct {
	ID           string
	Name         string
	URL          string
	SecretSealed string // sealed signing secret; empty = unsigned
	HasSecret    bool   // derived: a signing secret is configured
	Events       []string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// EventsLabel renders the subscribed categories for display: "All events" when
// none are selected (meaning every category), otherwise the capitalized list.
func (w Webhook) EventsLabel() string {
	if len(w.Events) == 0 {
		return "All events"
	}
	labels := make([]string, 0, len(w.Events))
	for _, e := range w.Events {
		if e == "" {
			continue
		}
		labels = append(labels, strings.ToUpper(e[:1])+e[1:])
	}
	return strings.Join(labels, ", ")
}

// WebhookInput holds the editable fields of a webhook. SecretSealed is a pointer
// so an update can distinguish "leave the stored secret unchanged" (nil) from
// "set/clear it" (non-nil, where "" clears).
type WebhookInput struct {
	Name         string
	URL          string
	SecretSealed *string
	Events       []string
	Enabled      bool
}

// WebhookDelivery is one recorded delivery attempt, for the settings log.
type WebhookDelivery struct {
	ID          int64
	WebhookID   string
	WebhookName string
	EventType   string
	Status      string // "success" | "failed"
	StatusCode  int
	Error       string
	CreatedAt   time.Time
}

const webhookDeliveryCap = 20

func (s *Store) CreateWebhook(ctx context.Context, input WebhookInput) (Webhook, error) {
	id, err := auth.RandomToken(12)
	if err != nil {
		return Webhook{}, err
	}
	sealed := ""
	if input.SecretSealed != nil {
		sealed = *input.SecretSealed
	}
	events := input.Events
	if events == nil {
		events = []string{}
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO webhooks (id, name, url, secret_sealed, events, enabled)
VALUES ($1, $2, $3, $4, $5, $6)`,
		id, input.Name, input.URL, sealed, events, input.Enabled); err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	return s.GetWebhook(ctx, id)
}

// UpdateWebhook updates a webhook. When input.SecretSealed is nil the stored
// secret is preserved; otherwise it is replaced (an empty string clears it).
func (s *Store) UpdateWebhook(ctx context.Context, id string, input WebhookInput) (Webhook, error) {
	events := input.Events
	if events == nil {
		events = []string{}
	}
	tag, err := s.db.Exec(ctx, `
UPDATE webhooks
SET name = $2, url = $3, secret_sealed = COALESCE($4, secret_sealed), events = $5, enabled = $6, updated_at = now()
WHERE id = $1`,
		id, input.Name, input.URL, input.SecretSealed, events, input.Enabled)
	if err != nil {
		return Webhook{}, fmt.Errorf("update webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Webhook{}, ErrNotFound
	}
	return s.GetWebhook(ctx, id)
}

func (s *Store) GetWebhook(ctx context.Context, id string) (Webhook, error) {
	var wh Webhook
	if err := s.db.QueryRow(ctx, `
SELECT id, name, url, secret_sealed, events, enabled, created_at, updated_at
FROM webhooks WHERE id = $1`, id).Scan(
		&wh.ID, &wh.Name, &wh.URL, &wh.SecretSealed, &wh.Events, &wh.Enabled, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return Webhook{}, ErrNotFound
		}
		return Webhook{}, fmt.Errorf("get webhook: %w", err)
	}
	wh.HasSecret = wh.SecretSealed != ""
	return wh, nil
}

func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `
SELECT id, name, url, secret_sealed, events, enabled, created_at, updated_at
FROM webhooks ORDER BY name`)
}

// ListEnabledWebhooks returns only enabled webhooks, for the dispatcher.
func (s *Store) ListEnabledWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `
SELECT id, name, url, secret_sealed, events, enabled, created_at, updated_at
FROM webhooks WHERE enabled ORDER BY name`)
}

func (s *Store) queryWebhooks(ctx context.Context, query string) ([]Webhook, error) {
	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()
	var hooks []Webhook
	for rows.Next() {
		var wh Webhook
		if err := rows.Scan(&wh.ID, &wh.Name, &wh.URL, &wh.SecretSealed, &wh.Events, &wh.Enabled, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		wh.HasSecret = wh.SecretSealed != ""
		hooks = append(hooks, wh)
	}
	return hooks, rows.Err()
}

func (s *Store) DeleteWebhook(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM webhooks WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountEnabledWebhooks reports how many webhooks are active, so the dispatcher can
// short-circuit the change feed when none are configured.
func (s *Store) CountEnabledWebhooks(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM webhooks WHERE enabled").Scan(&n); err != nil {
		return 0, fmt.Errorf("count enabled webhooks: %w", err)
	}
	return n, nil
}

// RecordWebhookDelivery appends a delivery attempt and prunes the per-webhook log
// to its cap so the table stays bounded.
func (s *Store) RecordWebhookDelivery(ctx context.Context, d WebhookDelivery) error {
	if _, err := s.db.Exec(ctx, `
INSERT INTO webhook_deliveries (webhook_id, event_type, status, status_code, error)
VALUES ($1, $2, $3, $4, $5)`, d.WebhookID, d.EventType, d.Status, d.StatusCode, d.Error); err != nil {
		return fmt.Errorf("record webhook delivery: %w", err)
	}
	if _, err := s.db.Exec(ctx, `
DELETE FROM webhook_deliveries
WHERE webhook_id = $1
  AND id NOT IN (SELECT id FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY id DESC LIMIT $2)`,
		d.WebhookID, webhookDeliveryCap); err != nil {
		return fmt.Errorf("prune webhook deliveries: %w", err)
	}
	return nil
}

// ListWebhookDeliveries returns the most recent delivery attempts across all
// webhooks (with the webhook name) for the settings log.
func (s *Store) ListWebhookDeliveries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(ctx, `
SELECT d.id, d.webhook_id, COALESCE(w.name, ''), d.event_type, d.status, d.status_code, d.error, d.created_at
FROM webhook_deliveries d
LEFT JOIN webhooks w ON w.id = d.webhook_id
ORDER BY d.created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()
	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.WebhookName, &d.EventType, &d.Status, &d.StatusCode, &d.Error, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
