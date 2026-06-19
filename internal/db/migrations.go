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

CREATE TABLE IF NOT EXISTS subnets (
	id text PRIMARY KEY,
	site_id text REFERENCES sites(id) ON DELETE SET NULL,
	cidr cidr NOT NULL,
	name text NOT NULL,
	vlan integer CHECK (vlan IS NULL OR vlan BETWEEN 1 AND 4094),
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
	vendor text NOT NULL DEFAULT '',
	is_private boolean NOT NULL DEFAULT false,
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
CREATE INDEX IF NOT EXISTS idx_ip_addresses_device_id ON ip_addresses (device_id);
CREATE INDEX IF NOT EXISTS idx_mac_addresses_device_id ON mac_addresses (device_id);

INSERT INTO sites (id, name, description)
VALUES ('default', 'Default', 'Initial site for this Light IPAM installation.')
ON CONFLICT (id) DO NOTHING;
`,
	},
	{
		version: 2,
		sql: `
ALTER TABLE subnets ADD COLUMN IF NOT EXISTS vlan integer CHECK (vlan IS NULL OR vlan BETWEEN 1 AND 4094);

INSERT INTO sites (id, name, description)
VALUES ('default', 'Default', 'Initial site for this Light IPAM installation.')
ON CONFLICT (id) DO NOTHING;
`,
	},
	{
		version: 3,
		sql: `
ALTER TABLE mac_addresses ADD COLUMN IF NOT EXISTS vendor text NOT NULL DEFAULT '';
ALTER TABLE mac_addresses ADD COLUMN IF NOT EXISTS is_private boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_ip_addresses_device_id ON ip_addresses (device_id);
CREATE INDEX IF NOT EXISTS idx_mac_addresses_device_id ON mac_addresses (device_id);

INSERT INTO tags (id, name, color)
VALUES ('private-mac', 'Private MAC', 'amber')
ON CONFLICT (id) DO NOTHING;
`,
	},
	{
		version: 4,
		sql: `
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'audit_logs are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_prevent_update ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_prevent_delete ON audit_logs;

CREATE TRIGGER audit_logs_prevent_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

CREATE TRIGGER audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();
`,
	},
	{
		version: 5,
		sql: `
CREATE TABLE IF NOT EXISTS scan_agents (
	id text PRIMARY KEY,
	name text NOT NULL,
	site_id text REFERENCES sites(id) ON DELETE SET NULL,
	endpoint_url text NOT NULL,
	certificate_subject text NOT NULL DEFAULT '',
	allowed_cidrs text[] NOT NULL DEFAULT '{}',
	status text NOT NULL DEFAULT 'pending',
	version text NOT NULL DEFAULT '',
	last_seen_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_schedules (
	id text PRIMARY KEY,
	name text NOT NULL,
	agent_id text NOT NULL REFERENCES scan_agents(id) ON DELETE CASCADE,
	scan_type text NOT NULL,
	mode text NOT NULL,
	allowed_cidrs text[] NOT NULL DEFAULT '{}',
	targets text[] NOT NULL DEFAULT '{}',
	timeout_seconds integer NOT NULL DEFAULT 60,
	interval_seconds integer NOT NULL,
	enabled boolean NOT NULL DEFAULT true,
	last_run_at timestamptz,
	next_run_at timestamptz NOT NULL DEFAULT now(),
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
	id text PRIMARY KEY,
	agent_id text NOT NULL REFERENCES scan_agents(id) ON DELETE CASCADE,
	schedule_id text REFERENCES scan_schedules(id) ON DELETE SET NULL,
	requested_by text REFERENCES users(id) ON DELETE SET NULL,
	scan_type text NOT NULL,
	mode text NOT NULL,
	allowed_cidrs text[] NOT NULL DEFAULT '{}',
	targets text[] NOT NULL DEFAULT '{}',
	timeout_seconds integer NOT NULL DEFAULT 60,
	status text NOT NULL DEFAULT 'queued',
	error text NOT NULL DEFAULT '',
	result jsonb,
	started_at timestamptz,
	finished_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_agent_id ON scan_jobs (agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules (next_run_at) WHERE enabled;
`,
	},
	{
		version: 6,
		sql: `
CREATE TABLE IF NOT EXISTS scan_discoveries (
	id text PRIMARY KEY,
	job_id text REFERENCES scan_jobs(id) ON DELETE SET NULL,
	agent_id text REFERENCES scan_agents(id) ON DELETE SET NULL,
	ip inet NOT NULL UNIQUE,
	mac macaddr,
	hostname text NOT NULL DEFAULT '',
	os_family text NOT NULL DEFAULT '',
	os_detail text NOT NULL DEFAULT '',
	services jsonb NOT NULL DEFAULT '[]'::jsonb,
	status text NOT NULL DEFAULT 'pending',
	imported_address_id text REFERENCES ip_addresses(id) ON DELETE SET NULL,
	imported_device_id text REFERENCES devices(id) ON DELETE SET NULL,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_discoveries_status ON scan_discoveries (status);
CREATE INDEX IF NOT EXISTS idx_scan_discoveries_last_seen ON scan_discoveries (last_seen_at DESC);
`,
	},
	{
		version: 7,
		sql: `
-- Reconciliation of a discovery against existing IPAM records:
--   new      = the address is not managed yet
--   match    = the address is managed and consistent with the observation
--   conflict = the observation disagrees with a managed record (MAC/state)
ALTER TABLE scan_discoveries ADD COLUMN IF NOT EXISTS reconcile_status text NOT NULL DEFAULT 'new';
ALTER TABLE scan_discoveries ADD COLUMN IF NOT EXISTS conflict text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scan_discoveries_reconcile ON scan_discoveries (reconcile_status);
`,
	},
	{
		version: 8,
		sql: `
-- Per-agent trust setting. When enabled, non-conflicting observations from this
-- agent are imported into IPAM automatically instead of waiting in the review
-- queue. Conflicts always stay pending for an operator to resolve.
ALTER TABLE scan_agents ADD COLUMN IF NOT EXISTS auto_import boolean NOT NULL DEFAULT false;
`,
	},
	{
		version: 9,
		sql: `
-- Discovery-derived inventory carried on the device record itself, so an
-- imported host surfaces everything the scan exposed (OS guess, open services,
-- and which agent first reported it) on the Devices page, not just under
-- Subnets. These are populated on import and refreshed on re-import.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_family text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_detail text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS services jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS discovery_source text NOT NULL DEFAULT '';
`,
	},
	{
		version: 10,
		sql: `
-- MAC vendor as reported by the scanner (nmap reads it from the OUI database
-- bundled with the agent, which is far more complete than our small built-in
-- table). Carried through the discovery so import can prefer it over the
-- app's best-effort OUI match.
ALTER TABLE scan_discoveries ADD COLUMN IF NOT EXISTS vendor text NOT NULL DEFAULT '';
`,
	},
	{
		version: 11,
		sql: `
-- 802.1Q access VLAN discovered for a host's interface during an snmp_inventory
-- scan (dot1qPvid, joined through the bridge-port table). 0 means unknown. On
-- import/re-sync, a non-zero VLAN fills the containing subnet's VLAN when it has
-- none, so VLAN findings reach the Subnets page; an existing VLAN is never
-- overwritten.
ALTER TABLE scan_discoveries ADD COLUMN IF NOT EXISTS vlan integer NOT NULL DEFAULT 0;
`,
	},
	{
		version: 12,
		sql: `
-- Phase 5 auth + session hardening.
--
-- login_attempts records each failed local login, keyed by both the attempted
-- username and the client IP, so the login handler can throttle and lock out
-- brute-force attempts. Rows are pruned by time window at read; a successful
-- login clears the matching username's rows.
CREATE TABLE IF NOT EXISTS login_attempts (
	id bigserial PRIMARY KEY,
	username text NOT NULL DEFAULT '',
	ip text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts (username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip, created_at DESC);

-- Session hardening: track activity for an idle timeout and capture the client
-- origin so an operator can review and revoke active sessions.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_ip text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent text NOT NULL DEFAULT '';
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
