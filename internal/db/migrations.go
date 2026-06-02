package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		sql: `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version integer PRIMARY KEY,
	applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
	id text PRIMARY KEY,
	username text NOT NULL UNIQUE,
	display_name text NOT NULL,
	password_hash text NOT NULL,
	is_admin boolean NOT NULL DEFAULT false,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf_token text NOT NULL,
	expires_at timestamptz NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id bigserial PRIMARY KEY,
	actor_user_id text REFERENCES users(id) ON DELETE SET NULL,
	action text NOT NULL,
	subject_type text NOT NULL,
	subject_id text,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE address_state AS ENUM ('available', 'reserved', 'assigned', 'deprecated', 'conflict');

CREATE TABLE IF NOT EXISTS sites (
	id text PRIMARY KEY,
	name text NOT NULL UNIQUE,
	description text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vlans (
	id text PRIMARY KEY,
	site_id text REFERENCES sites(id) ON DELETE SET NULL,
	vlan_id integer NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
	name text NOT NULL,
	description text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (site_id, vlan_id)
);

CREATE TABLE IF NOT EXISTS subnets (
	id text PRIMARY KEY,
	site_id text REFERENCES sites(id) ON DELETE SET NULL,
	vlan_id text REFERENCES vlans(id) ON DELETE SET NULL,
	cidr cidr NOT NULL,
	name text NOT NULL,
	description text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (cidr)
);

CREATE TABLE IF NOT EXISTS devices (
	id text PRIMARY KEY,
	name text NOT NULL,
	description text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_addresses (
	id text PRIMARY KEY,
	subnet_id text REFERENCES subnets(id) ON DELETE SET NULL,
	device_id text REFERENCES devices(id) ON DELETE SET NULL,
	address inet NOT NULL UNIQUE,
	state address_state NOT NULL DEFAULT 'available',
	hostname text NOT NULL DEFAULT '',
	notes text NOT NULL DEFAULT '',
	last_seen_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mac_addresses (
	id text PRIMARY KEY,
	device_id text REFERENCES devices(id) ON DELETE CASCADE,
	address macaddr NOT NULL UNIQUE,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tags (
	id text PRIMARY KEY,
	name text NOT NULL UNIQUE,
	color text NOT NULL DEFAULT 'slate',
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS taggings (
	tag_id text NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
	entity_type text NOT NULL,
	entity_id text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tag_id, entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS custom_fields (
	id text PRIMARY KEY,
	entity_type text NOT NULL,
	name text NOT NULL,
	field_type text NOT NULL DEFAULT 'text',
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (entity_type, name)
);

CREATE TABLE IF NOT EXISTS custom_field_values (
	custom_field_id text NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
	entity_id text NOT NULL,
	value text NOT NULL DEFAULT '',
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (custom_field_id, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_subnets_cidr ON subnets USING gist (cidr inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_addresses_address ON ip_addresses USING gist (address inet_ops);
`,
	},
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version integer PRIMARY KEY,
	applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	for _, migration := range migrations {
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", migration.version).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %d: %w", migration.version, err)
		}
		if exists {
			continue
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.version, err)
		}

		if _, err := tx.Exec(ctx, migration.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %d: %w", migration.version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", migration.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", migration.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.version, err)
		}
	}

	return nil
}
