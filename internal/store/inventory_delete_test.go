package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInventoryDeletionAndDiscoveryReimport(t *testing.T) {
	ctx := context.Background()
	st, pool := newIntegrationStore(t, ctx)
	mustExec(t, ctx, pool, `INSERT INTO subnets (id, site_id, cidr, name) VALUES ('subnet-test', 'default', '10.0.0.0/24', 'Test LAN')`)

	t.Run("device deletion removes its addresses", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-delete", "10.0.0.10")
		if err := st.DeleteDevice(ctx, "device-delete"); err != nil {
			t.Fatalf("DeleteDevice: %v", err)
		}
		assertCount(t, ctx, pool, "SELECT count(*) FROM devices WHERE id = 'device-delete'", 0)
		assertCount(t, ctx, pool, "SELECT count(*) FROM ip_addresses WHERE address = '10.0.0.10'::inet", 0)
	})

	t.Run("last address deletion removes its device", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-last-address", "10.0.0.20")
		if err := st.DeleteAddress(ctx, "address-device-last-address-0"); err != nil {
			t.Fatalf("DeleteAddress: %v", err)
		}
		assertCount(t, ctx, pool, "SELECT count(*) FROM devices WHERE id = 'device-last-address'", 0)
	})

	t.Run("one address deletion preserves a multi-address device", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-multi", "10.0.0.30", "10.0.0.31")
		if err := st.DeleteAddress(ctx, "address-device-multi-0"); err != nil {
			t.Fatalf("DeleteAddress: %v", err)
		}
		assertCount(t, ctx, pool, "SELECT count(*) FROM devices WHERE id = 'device-multi'", 1)
		assertCount(t, ctx, pool, "SELECT count(*) FROM ip_addresses WHERE device_id = 'device-multi'", 1)
	})

	t.Run("bulk device deletion removes associated addresses", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-bulk-delete-a", "10.0.0.50")
		seedDevice(t, ctx, pool, "device-bulk-delete-b", "10.0.0.51")
		count, err := st.BulkDeleteDevices(ctx, []string{"device-bulk-delete-a", "device-bulk-delete-b"})
		if err != nil {
			t.Fatalf("BulkDeleteDevices: %v", err)
		}
		if count != 2 {
			t.Fatalf("BulkDeleteDevices count = %d, want 2", count)
		}
		assertCount(t, ctx, pool, "SELECT count(*) FROM ip_addresses WHERE address <<= '10.0.0.50/31'::cidr", 0)
	})

	t.Run("bulk address deletion removes orphan devices", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-bulk-address-a", "10.0.0.60")
		seedDevice(t, ctx, pool, "device-bulk-address-b", "10.0.0.61", "10.0.0.62")
		count, err := st.BulkDeleteAddresses(ctx, []string{"address-device-bulk-address-a-0", "address-device-bulk-address-b-0"})
		if err != nil {
			t.Fatalf("BulkDeleteAddresses: %v", err)
		}
		if count != 2 {
			t.Fatalf("BulkDeleteAddresses count = %d, want 2", count)
		}
		assertCount(t, ctx, pool, "SELECT count(*) FROM devices WHERE id = 'device-bulk-address-a'", 0)
		assertCount(t, ctx, pool, "SELECT count(*) FROM devices WHERE id = 'device-bulk-address-b'", 1)
		assertCount(t, ctx, pool, "SELECT count(*) FROM ip_addresses WHERE device_id = 'device-bulk-address-b'", 1)
	})

	t.Run("rescan reopens a deleted import", func(t *testing.T) {
		seedDevice(t, ctx, pool, "device-reimport", "10.0.0.40")
		mustExec(t, ctx, pool, `
INSERT INTO scan_discoveries (id, ip, hostname, status, reconcile_status, imported_address_id, imported_device_id)
VALUES ('discovery-reimport', '10.0.0.40'::inet, 'printer.test', 'imported', 'match', 'address-device-reimport-0', 'device-reimport')`)

		if err := st.DeleteDevice(ctx, "device-reimport"); err != nil {
			t.Fatalf("DeleteDevice: %v", err)
		}
		upsert, err := st.UpsertDiscovery(ctx, DiscoveryInput{IP: "10.0.0.40", Hostname: "printer.test"})
		if err != nil {
			t.Fatalf("UpsertDiscovery: %v", err)
		}
		if upsert.ReconcileStatus != ReconcileNew || upsert.ReviewStatus != "pending" {
			t.Fatalf("rescan status = %s/%s, want new/pending", upsert.ReconcileStatus, upsert.ReviewStatus)
		}

		imported, err := st.ImportDiscovery(ctx, upsert.ID, "")
		if err != nil {
			t.Fatalf("ImportDiscovery: %v", err)
		}
		if imported.ImportedAddressID == "" || imported.ImportedDeviceID == "" {
			t.Fatalf("re-import did not create managed inventory: %+v", imported)
		}
		if imported.ImportedDeviceID == "device-reimport" {
			t.Fatal("re-import reused the deleted device id")
		}
	})

	t.Run("rescan preserves dismissed and still-managed review decisions", func(t *testing.T) {
		mustExec(t, ctx, pool, `
INSERT INTO scan_discoveries (id, ip, status, reconcile_status)
VALUES ('discovery-dismissed', '10.0.0.70'::inet, 'dismissed', 'new')`)
		dismissed, err := st.UpsertDiscovery(ctx, DiscoveryInput{IP: "10.0.0.70"})
		if err != nil {
			t.Fatalf("UpsertDiscovery dismissed: %v", err)
		}
		if dismissed.ReviewStatus != "dismissed" {
			t.Fatalf("dismissed rescan status = %s, want dismissed", dismissed.ReviewStatus)
		}

		mustExec(t, ctx, pool, `
INSERT INTO ip_addresses (id, subnet_id, address, state)
VALUES ('address-still-managed', 'subnet-test', '10.0.0.71'::inet, 'assigned')`)
		mustExec(t, ctx, pool, `
INSERT INTO scan_discoveries (id, ip, status, reconcile_status)
VALUES ('discovery-still-managed', '10.0.0.71'::inet, 'imported', 'new')`)
		managed, err := st.UpsertDiscovery(ctx, DiscoveryInput{IP: "10.0.0.71"})
		if err != nil {
			t.Fatalf("UpsertDiscovery managed: %v", err)
		}
		if managed.ReconcileStatus != ReconcileMatch || managed.ReviewStatus != "imported" {
			t.Fatalf("managed rescan status = %s/%s, want match/imported", managed.ReconcileStatus, managed.ReviewStatus)
		}
	})
}

func newIntegrationStore(t *testing.T, ctx context.Context) (*Store, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("LIGHTIPAM_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set LIGHTIPAM_TEST_DATABASE_URL to run PostgreSQL store integration tests")
	}

	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	schema := fmt.Sprintf("lightipam_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatalf("parse test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	return New(pool), pool
}

func seedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID string, addresses ...string) {
	t.Helper()
	mustExec(t, ctx, pool, "INSERT INTO devices (id, name) VALUES ($1, $2)", deviceID, deviceID)
	for i, address := range addresses {
		mustExec(t, ctx, pool, `
INSERT INTO ip_addresses (id, subnet_id, device_id, address, state)
VALUES ($1, 'subnet-test', $2, $3::inet, 'assigned')`, fmt.Sprintf("address-%s-%d", deviceID, i), deviceID, address)
	}
}

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, query, args...); err != nil {
		t.Fatalf("exec test query: %v", err)
	}
}

func assertCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(ctx, query).Scan(&got); err != nil {
		t.Fatalf("query count: %v", err)
	}
	if got != want {
		t.Fatalf("count = %d, want %d", got, want)
	}
}
