package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/auth"
)

// Bulk operations apply a single change to a set of entities selected in the UI.
// Every method is a single statement scoped by `id = ANY($ids)`, so it touches
// only the selected rows and reports how many it changed for the audit trail.
// Tagging reuses the shared taggings table (entity_type in subnet/ip_address/
// device), mirroring TagDevice's seed-the-tag-then-link pattern.

// BulkSetAddressState sets the state of the given addresses. The caller must have
// already validated state against the address_state enum.
func (s *Store) BulkSetAddressState(ctx context.Context, ids []string, state string) (int, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE ip_addresses
SET state = $2::address_state, updated_at = now()
WHERE id = ANY($1)`, ids, state)
	if err != nil {
		return 0, fmt.Errorf("bulk set address state: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkClearAddressDevice detaches the linked device from the given addresses.
func (s *Store) BulkClearAddressDevice(ctx context.Context, ids []string) (int, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE ip_addresses
SET device_id = NULL, updated_at = now()
WHERE id = ANY($1)`, ids)
	if err != nil {
		return 0, fmt.Errorf("bulk clear address device: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkDeleteAddresses removes the given sparse address records.
func (s *Store) BulkDeleteAddresses(ctx context.Context, ids []string) (int, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM ip_addresses WHERE id = ANY($1)", ids)
	if err != nil {
		return 0, fmt.Errorf("bulk delete addresses: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkSetSubnetVLAN sets (or, with a nil vlan, clears) the VLAN on the given
// subnets. The caller must have validated vlan via ParseVLAN.
func (s *Store) BulkSetSubnetVLAN(ctx context.Context, ids []string, vlan *int) (int, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE subnets
SET vlan = $2, updated_at = now()
WHERE id = ANY($1)`, ids, vlan)
	if err != nil {
		return 0, fmt.Errorf("bulk set subnet vlan: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkDeleteSubnets removes the given subnets. Touched address records are
// detached (subnets.id is ON DELETE SET NULL from ip_addresses), matching the
// single-subnet delete.
func (s *Store) BulkDeleteSubnets(ctx context.Context, ids []string) (int, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM subnets WHERE id = ANY($1)", ids)
	if err != nil {
		return 0, fmt.Errorf("bulk delete subnets: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkDeleteDevices removes the given devices. Their MAC records cascade and
// linked IP records are left unassigned, matching the single-device delete.
func (s *Store) BulkDeleteDevices(ctx context.Context, ids []string) (int, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM devices WHERE id = ANY($1)", ids)
	if err != nil {
		return 0, fmt.Errorf("bulk delete devices: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkAddTag ensures a tag with the given (case-preserving, unique) name exists
// and links it to every selected entity. entityType is one of "subnet",
// "ip_address", or "device". It returns the number of new links created (links
// that already existed are left untouched).
func (s *Store) BulkAddTag(ctx context.Context, entityType string, ids []string, name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("tag name is required")
	}
	id, err := auth.RandomToken(12)
	if err != nil {
		return 0, err
	}
	var tagID string
	if err := s.db.QueryRow(ctx, `
INSERT INTO tags (id, name, color)
VALUES ($1, $2, 'slate')
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING id`, id, name).Scan(&tagID); err != nil {
		return 0, fmt.Errorf("ensure tag: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO taggings (tag_id, entity_type, entity_id)
SELECT $1, $2, unnest($3::text[])
ON CONFLICT DO NOTHING`, tagID, entityType, ids)
	if err != nil {
		return 0, fmt.Errorf("bulk add tag: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// BulkRemoveTag unlinks the named tag from every selected entity. A name that
// matches no tag removes nothing and is not an error. The tag definition itself
// is left in place (it may still be used elsewhere).
func (s *Store) BulkRemoveTag(ctx context.Context, entityType string, ids []string, name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("tag name is required")
	}
	tag, err := s.db.Exec(ctx, `
DELETE FROM taggings
WHERE entity_type = $1
AND entity_id = ANY($2)
AND tag_id = (SELECT id FROM tags WHERE name = $3)`, entityType, ids, name)
	if err != nil {
		return 0, fmt.Errorf("bulk remove tag: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
