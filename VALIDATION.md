# Validation — 0.3.0

Verified locally on 2026-10-10–11. These checks do not assert that a production
Active Directory, Tempo endpoint, Kubernetes network or Argo CD installation works.

- **54 Python tests passed, none skipped**, using Python 3.13, a real disposable
  PostgreSQL 17 database and two HTTP application instances. The full suite also
  passed inside the release image with a read-only filesystem, UID 10001,
  dropped capabilities, 256 MiB memory and 0.5 CPU.
- LDAP bind is mocked in the integration suite. Unit tests verify own-user bind,
  escaped UPN lookup, exact single-result validation, timeouts and no referrals.
- Shared sessions, viewer/admin restrictions, atomic bans and session revocation,
  logout, Origin/CSRF validation, export authorization, concurrent login rate
  limits and bounded metric labels are covered. A real PostgreSQL constraint
  failure verifies that required audit failure blocks trace access.
- Fake Tempo HTTP tests cover forwarding, upstream credentials, redirect refusal,
  invalid/oversized responses, timeouts and readiness during concurrent searches.
  Regression tests cover log sanitization and the total request-input deadline.
- Chromium with a synthetic authentication backend verified login failure,
  viewer/admin navigation, download, ban, logout, session expiry, XSS escaping,
  browser audit events and 390 px layouts, without JavaScript errors.
- Helm strict lint and three rendered configurations passed: bundled PostgreSQL,
  NodePort, and external PostgreSQL with ServiceMonitor. Nine incomplete or unsafe
  configuration examples were rejected. Rendering is not a live CNI test.
- The bundled PostgreSQL image started under UID 70, a read-only root filesystem,
  dropped capabilities, 256 MiB memory and 0.5 CPU using writable runtime/data
  mounts. The single database instance is not an HA deployment.
  A separate fresh initialization verified a non-superuser application role,
  TCP password login (including quoting characters), schema/table writes and
  rejection of CREATE ROLE; bootstrap and application passwords are separate.
- Ansible syntax passed. Single-source and public-chart/private-values Application
  assembly both passed local execution with Kubernetes mutation tasks removed.
- The published `linux/amd64` image archive passed `docker load` and direct
  inspection: classic `manifest.json` plus config and ten uncompressed layers,
  without OCI layout/index/blob paths. Config/layer hashes and application source
  files matched the release source.
- The Docker archive converter passed synthetic plain, gzip and zstd layer cases,
  verifies decompressed layer hashes, and refuses to overwrite existing output.

Run the server checks against a **disposable** database whose name ends in `_test`:

```bash
python -m pip install -r requirements.txt
TEST_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/traceyard_test \
  python -B -m unittest discover -s tests -v
```

Without `TEST_DATABASE_URL`, the 12 PostgreSQL integration tests are skipped.
The database guard rejects ordinary database names before connecting; tests clear
Traceyard tables in the selected test database.

Before an installation is considered verified, exercise real directory login,
Tempo search/export, bans across both pods, client IP forwarding, Prometheus
scraping, DNS/LDAP/Tempo NetworkPolicy connectivity and Argo CD synchronization.
Use load measurements to tune the initial resource limits and audit PVC size.
