# Light IPAM

Light IPAM is a lightweight IP address management system with a web UI and controlled network discovery.

The core design is intentionally split:

- `app`: unprivileged web UI, API, auth, inventory, audit logs, and scan orchestration.
- `scanner-agent`: optional privileged network sensor with narrow capabilities for discovery, OS probing, and service detection.
- `db`: PostgreSQL storage using native network-aware types such as `inet` and `cidr`.

## Recommended Stack

- Backend: Go, standard `net/http` to start, `pgx` for PostgreSQL, `sqlc` for typed queries, `goose` for migrations.
- Frontend: server-rendered HTML with HTMX and a small amount of TypeScript where needed.
- Database: PostgreSQL.
- Scanner agent: Go orchestration around approved scanners such as Nmap, plus passive collectors where available.
- Deployment: Docker Compose for small installs, Kubernetes later if multi-site scale needs it.

## Local Run

```sh
docker compose up --build
```

Then open `http://localhost:8080`.

## Project Status

This repository is at the planning and scaffold stage. See:

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [MVP Requirements](docs/MVP.md)
- [Roadmap](docs/ROADMAP.md)
