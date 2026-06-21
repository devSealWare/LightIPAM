# NetBox-compatible import / export

Light IPAM can read and write CSV in [NetBox](https://netbox.dev/)'s column format so
you can move prefixes, IP addresses, and devices between the two systems. Select
**NetBox** as the format on the **Import / Export** page (or use the **Export NetBox**
links). A NetBox upload is translated into Light IPAM's native columns and then runs
through the **exact same dry-run preview and all-or-nothing apply** as a native CSV —
nothing changes until you confirm, and an invalid file is never partially applied.

Import order still matters: import **devices**, then **subnets** (prefixes), then
**addresses**, so device links and subnet containment resolve.

## Column mapping

The object models do not line up perfectly. NetBox **prefixes have no name** (only a
description), and NetBox **devices require a role / type / site** that Light IPAM does
not model. The IPAM core — prefixes ↔ subnets and IP addresses — maps cleanly; the
edges below are intentionally lossy and documented.

### Prefixes ↔ subnets

| NetBox column | Light IPAM | Notes |
| --- | --- | --- |
| `prefix` | `cidr` | Required. IPv4 only. |
| `vlan_vid` (or `vlan_id`, `vlan`) | `vlan` | Optional VLAN id. |
| `site` | `site` | Matched to an existing site by name. |
| `description` | `name` **and** `description` | NetBox prefixes have no name, so the description becomes the Light IPAM subnet name (and is kept as the description). If `description` is empty, the prefix string is used as the name. |
| `status`, `tenant`, `vrf`, `role`, … | — | Ignored on import. |

On **export**, Light IPAM emits `prefix, status, vlan_vid, site, description` with
`status` fixed to `active` and the subnet **name** placed in `description` so it
round-trips back as the name. A separate free-text Light IPAM description is not
represented in a NetBox prefix CSV.

### IP addresses

| NetBox column | Light IPAM | Notes |
| --- | --- | --- |
| `address` | `address` | Required. The `/mask` suffix is stripped (Light IPAM stores host addresses); the containing subnet is located automatically and must already exist. |
| `status` | `state` | `active`/`dhcp`/`slaac`/empty → `assigned`; `reserved` → `reserved`; `deprecated` → `deprecated`. |
| `dns_name` | `hostname` | |
| `description` | `notes` | |
| interface / assigned object | — | NetBox interface assignment is not mapped to a Light IPAM device. |

On **export**, Light IPAM emits `address, status, dns_name, description`; the address
carries the containing subnet's mask (e.g. `10.0.0.5/24`, falling back to `/32`), and
`assigned`/`available`/`conflict` all map to NetBox `active` (NetBox has no
`available`/`conflict` status).

### Devices

| NetBox column | Light IPAM | Notes |
| --- | --- | --- |
| `name` | `name` | Required; keyed by name (a match updates, otherwise creates). |
| `description` (or `comments`) | `description` | |
| `device_role`, `device_type`, `manufacturer`, `site`, … | — | Ignored on import. |

On **export**, Light IPAM emits `name, status, description` with `status` fixed to
`active`. Because NetBox device import requires a role, type, and site that Light IPAM
does not store, a Light IPAM device export is **not** directly importable into NetBox
without adding those columns; the prefix and IP-address exports are the directly
round-trippable ones.

## Validation

Every translated row is validated against the same rules as the native importer and the
on-screen forms: IPv4 CIDRs (including `/31` and `/32`), global subnet-overlap blocking
(a matching CIDR is an update), the sparse address model with containment, the
address-state enum, and exact-name device links. The dry-run preview shows the
translated Light IPAM values per row so you can see exactly how the NetBox file was
interpreted before applying.
