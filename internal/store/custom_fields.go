package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// Custom-field entity types. These match the entity_type values used by the
// taggings table so the two metadata systems describe the same objects.
const (
	CustomFieldSubnet  = "subnet"
	CustomFieldAddress = "ip_address"
	CustomFieldDevice  = "device"
)

// ValidCustomFieldEntityType reports whether entityType is one Light IPAM
// attaches custom fields to.
func ValidCustomFieldEntityType(entityType string) bool {
	switch entityType {
	case CustomFieldSubnet, CustomFieldAddress, CustomFieldDevice:
		return true
	default:
		return false
	}
}

// CustomFieldDef is an operator-defined extra attribute for an entity type. The
// MVP supports a single field type ("text"); the field_type column leaves room
// for richer types later without a schema change.
type CustomFieldDef struct {
	ID         string
	EntityType string
	Name       string
	FieldType  string
	CreatedAt  time.Time
}

// CustomFieldValue pairs a field definition with the value stored for a specific
// entity (empty when the entity has no value for that field).
type CustomFieldValue struct {
	Def   CustomFieldDef
	Value string
}

// ListAllCustomFieldDefs returns every custom-field definition, ordered by
// entity type then name, for the management UI.
func (s *Store) ListAllCustomFieldDefs(ctx context.Context) ([]CustomFieldDef, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, entity_type, name, field_type, created_at
FROM custom_fields
ORDER BY entity_type, lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list custom fields: %w", err)
	}
	defer rows.Close()
	return scanCustomFieldDefs(rows)
}

// ListCustomFieldDefs returns the definitions for one entity type, ordered by
// name.
func (s *Store) ListCustomFieldDefs(ctx context.Context, entityType string) ([]CustomFieldDef, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, entity_type, name, field_type, created_at
FROM custom_fields
WHERE entity_type = $1
ORDER BY lower(name)`, entityType)
	if err != nil {
		return nil, fmt.Errorf("list custom fields: %w", err)
	}
	defer rows.Close()
	return scanCustomFieldDefs(rows)
}

func scanCustomFieldDefs(rows pgx.Rows) ([]CustomFieldDef, error) {
	var defs []CustomFieldDef
	for rows.Next() {
		var d CustomFieldDef
		if err := rows.Scan(&d.ID, &d.EntityType, &d.Name, &d.FieldType, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan custom field: %w", err)
		}
		defs = append(defs, d)
	}
	return defs, rows.Err()
}

// GetCustomFieldDef returns one definition by id.
func (s *Store) GetCustomFieldDef(ctx context.Context, id string) (CustomFieldDef, error) {
	var d CustomFieldDef
	if err := s.db.QueryRow(ctx, `
SELECT id, entity_type, name, field_type, created_at
FROM custom_fields
WHERE id = $1`, id).Scan(&d.ID, &d.EntityType, &d.Name, &d.FieldType, &d.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CustomFieldDef{}, ErrNotFound
		}
		return CustomFieldDef{}, fmt.Errorf("get custom field: %w", err)
	}
	return d, nil
}

// CreateCustomFieldDef defines a new custom field for an entity type. Names are
// unique per entity type (case-insensitively); a clash returns ErrDuplicate.
func (s *Store) CreateCustomFieldDef(ctx context.Context, entityType, name string) (CustomFieldDef, error) {
	name = strings.TrimSpace(name)
	if !ValidCustomFieldEntityType(entityType) {
		return CustomFieldDef{}, fmt.Errorf("invalid entity type %q", entityType)
	}
	if name == "" {
		return CustomFieldDef{}, errors.New("custom field name is required")
	}
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM custom_fields WHERE entity_type = $1 AND lower(name) = lower($2))`,
		entityType, name).Scan(&exists); err != nil {
		return CustomFieldDef{}, fmt.Errorf("check custom field: %w", err)
	}
	if exists {
		return CustomFieldDef{}, ErrDuplicate
	}
	id, err := auth.RandomToken(18)
	if err != nil {
		return CustomFieldDef{}, err
	}
	d := CustomFieldDef{ID: id, EntityType: entityType, Name: name, FieldType: "text"}
	if err := s.db.QueryRow(ctx, `
INSERT INTO custom_fields (id, entity_type, name, field_type)
VALUES ($1, $2, $3, $4)
RETURNING created_at`, d.ID, d.EntityType, d.Name, d.FieldType).Scan(&d.CreatedAt); err != nil {
		return CustomFieldDef{}, fmt.Errorf("create custom field: %w", err)
	}
	return d, nil
}

// DeleteCustomFieldDef removes a definition and (via ON DELETE CASCADE) every
// value stored for it.
func (s *Store) DeleteCustomFieldDef(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM custom_fields WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete custom field: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CustomFieldValues returns every definition for an entity type paired with the
// value stored for entityID (empty when unset). An empty entityID (a not-yet-
// created entity) yields the definitions with empty values, so the same call
// drives both new and edit forms.
func (s *Store) CustomFieldValues(ctx context.Context, entityType, entityID string) ([]CustomFieldValue, error) {
	rows, err := s.db.Query(ctx, `
SELECT cf.id, cf.entity_type, cf.name, cf.field_type, cf.created_at, COALESCE(v.value, '')
FROM custom_fields cf
LEFT JOIN custom_field_values v ON v.custom_field_id = cf.id AND v.entity_id = $2
WHERE cf.entity_type = $1
ORDER BY lower(cf.name)`, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("list custom field values: %w", err)
	}
	defer rows.Close()
	var values []CustomFieldValue
	for rows.Next() {
		var cv CustomFieldValue
		if err := rows.Scan(&cv.Def.ID, &cv.Def.EntityType, &cv.Def.Name, &cv.Def.FieldType, &cv.Def.CreatedAt, &cv.Value); err != nil {
			return nil, fmt.Errorf("scan custom field value: %w", err)
		}
		values = append(values, cv)
	}
	return values, rows.Err()
}

// SetCustomFieldValues stores values keyed by field-definition id for one
// entity. Storage is sparse: a blank value deletes the row. Only ids that
// belong to the entity type are touched, so an unexpected key is ignored; a
// definition absent from values is left unchanged.
func (s *Store) SetCustomFieldValues(ctx context.Context, entityType, entityID string, values map[string]string) error {
	if entityID == "" {
		return errors.New("entity id is required")
	}
	defs, err := s.ListCustomFieldDefs(ctx, entityType)
	if err != nil {
		return err
	}
	if len(defs) == 0 {
		return nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set custom field values: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, def := range defs {
		value, ok := values[def.ID]
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			if _, err := tx.Exec(ctx,
				`DELETE FROM custom_field_values WHERE custom_field_id = $1 AND entity_id = $2`,
				def.ID, entityID); err != nil {
				return fmt.Errorf("clear custom field value: %w", err)
			}
			continue
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO custom_field_values (custom_field_id, entity_id, value, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (custom_field_id, entity_id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			def.ID, entityID, value); err != nil {
			return fmt.Errorf("set custom field value: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit set custom field values: %w", err)
	}
	return nil
}
