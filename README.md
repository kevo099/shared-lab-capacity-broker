# Shared Lab Capacity Broker

Shared Lab Capacity Broker is a deterministic, read-only answer to a practical
question: **which reviewed lab environments can coexist now, and which
pre-approved workloads would have to donate capacity for another lab to fit?**

Version 0.1 includes a polished operations dashboard, pure capacity planner,
strict public schemas, fictional examples, a credential-side read-only
collector, and a credential-free live snapshot mode. It has no reservation
writer, approval endpoint, database, executor, or infrastructure mutation
route. Every proposed action is inert data.

The bundled topology is deliberately fictional: two invented nodes with 80
GiB and 72 GiB of memory, invented workload aliases, and invented placement
splits. It demonstrates behavior without documenting a contributor's estate.

## Highlights

- Conservative configured-maximum and diagnostic observed-memory envelopes.
- Explicit per-node reservations for cohorts that span hosts.
- One global exam slot, held through activation, release, and failed cleanup.
- Exact shared-cohort ownership and conflict checks.
- Donor selection from reviewed sets only, with backup and placement gates.
- Fail-closed handling for stale, missing, future, skewed, mismatched, or
  contradictory evidence.
- Nullable swap-rate evidence and a transport-neutral typed reader seam keep
  centralized visibility available while making plans on an unproven node
  unknown with no actions.
- Catalog-digest pinning across probe evidence, sanitized snapshots,
  application load, and plan output.
- A local, accessible, framework-free dashboard and bounded Prometheus metrics.
- Strict GET-only infrastructure collection and durable sanitized export.
- Standard-library-only runtime; JSON Schema validation is a pinned test extra.

The fictional fixture produces this matrix:

| Environment | Result | Donors |
|---|---|---|
| Cluster administration exam A | Safe now | None |
| Cluster administration exam B | Safe now | None |
| Linux operations exam | Safe now | None |
| Configuration automation exam | Safe now | None |
| Network security range | Safe with donors | Vision workbench |
| Enterprise desktop practice range | Safe with donors | Batch and archive workspaces |
| Vision workbench | Already active | None |

## Install and run

Python 3.12 through 3.14 is supported.

```bash
python3 -m pip install .
lab-broker overview
lab-broker plan security-range
lab-broker serve
```

Open `http://127.0.0.1:8087/`. Synthetic mode is visibly labeled and the UI
always states that no executor is installed.

For source-tree development:

```bash
export PYTHONPATH=src
python3 -m lab_broker overview
python3 -m lab_broker plan security-range
python3 -m lab_broker serve
```

The server binds to loopback unless `--allow-nonloopback` is explicitly used
for a protected synthetic demonstration. That flag adds neither TLS nor
authentication and is not a production mode.

## Read-only API

| Method and path | Purpose |
|---|---|
| `GET /api/v1/overview` | Node envelopes, exam slot, and environment matrix |
| `GET /api/v1/environments` | Environment summaries |
| `GET /api/v1/environments/{alias}` | One environment and its current plan |
| `POST /api/v1/plans` | Compute an in-memory plan from loopback only |
| `GET /metrics` | Bounded Prometheus exposition |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Snapshot readiness |

Example local computation:

```bash
curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data '{"environment_id":"security-range"}' \
  http://127.0.0.1:8087/api/v1/plans
```

`POST /api/v1/plans` does not persist or execute anything, but it is still
restricted to loopback. The supplied nginx fragment publishes GET/HEAD only.
PUT, PATCH, DELETE, CORS preflight, transfer encoding, duplicate keys, queries,
short or oversized bodies, and arbitrary identifiers are rejected.

Accepted HTTP sockets use a ten-second timeout for each blocking I/O operation;
this is not a total request deadline. Credential-side bounded read loops apply
their separately documented monotonic wall-clock limits.

## Live read-only mode

The collector keeps infrastructure credentials and private bindings on a
trusted administration host. It emits only a validated, semantic snapshot.
The application host receives that file and a matching reviewed catalog; it
has no infrastructure credential or private inventory map.

Exact inputs, trust boundaries, commands, systemd/nginx artifacts, and
operator gates are in [docs/LIVE-READ-ONLY.md](docs/LIVE-READ-ONLY.md).

Do not expose a live view until a reverse proxy provides reviewed TLS,
authentication, and rate limiting. The sample nginx snippet is intentionally a
path fragment, not a complete server.

## Test, validate, and build

```bash
python3 -m pip install '.[test]' build==1.3.0
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests scripts
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
python3 scripts/check_public_tree.py .
python3 -m build
systemd-analyze verify deploy/lab-broker-live.service deploy/lab-broker-synthetic.service
```

Tests cover domain arithmetic, strict parsing, catalog pinning, multi-node
cohorts, donor restrictions, collection shapes, frontend safety, HTTP
hardening, real JSON Schema validation, package-resource drift, and whole-tree
publication hygiene. CI additionally installs the built wheel into a clean
environment and runs the CLI from outside the checkout.

An optional private literal denylist can be supplied without committing it:

```bash
python3 scripts/check_public_tree.py . --denylist /secure/path/release-denylist.txt
```

Each nonblank, non-comment line is treated as a literal that must not appear in
the public tree.

## Project map

```text
src/lab_broker/domain/       immutable inputs and pure planner
src/lab_broker/data/         wheel-bundled fictional fixtures and schemas
src/lab_broker/live_export.py strict GET reader and sanitized atomic export
src/lab_broker/evidence_probe.py bounded read-only evidence producer
src/lab_broker/web.py        credential-free HTTP boundary
src/lab_broker/ui/static/    local dashboard assets
policies/ and fixtures/      reviewable source copies of public examples
deploy/                      contracts and review-only service/proxy artifacts
tests/                       domain, contract, integration, and hygiene tests
scripts/                     public-tree release scanner
```

The implemented architecture is in [DESIGN.md](DESIGN.md). Future PostgreSQL,
lease, approval, OpenTelemetry, and isolated executor work is in
[ROADMAP.md](ROADMAP.md).

## License and trademarks

Licensed under the [Apache License 2.0](LICENSE). This independent project is
not affiliated with or endorsed by infrastructure or certification vendors;
see [NOTICE.md](NOTICE.md).

Report security issues privately through
[GitHub's private vulnerability form](https://github.com/AoS-ssb/shared-lab-capacity-broker/security/advisories/new),
not a public issue.
