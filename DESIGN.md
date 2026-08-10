# Version 0.1 architecture

## Scope

Version 0.1 is a deterministic, read-only capacity planner. It answers whether
a reviewed lab can start from a complete evidence snapshot and, when needed,
which pre-approved workloads could donate capacity. It cannot reserve capacity,
approve a plan, invoke a controller, or mutate infrastructure.

The implementation has four boundaries:

```text
credential side                       credential-free application side

read-only infrastructure API          sanitized snapshot file
          |                                      |
private aliases + evidence probe                 v
          |                             pure deterministic planner
          v                                      |
strict sanitizer -- atomic file -----------------+
                                                 |
                                       loopback HTTP API + static UI
```

The public examples use a fictional two-node estate. Their names, capacities,
cohorts, and workload mix are test vectors, not deployment defaults.

## Components

### Immutable domain model

`src/lab_broker/domain` contains exact parsers and the planning function. The
package has no filesystem, environment, network, process, database, or wall
clock access. Callers provide an immutable catalog, immutable snapshot, and an
explicit evaluation time.

The catalog defines:

- semantic environment and guest aliases;
- environment class (`exam`, `application`, or `core`);
- exact single- or multi-node cohort placements;
- per-node memory reserves and root-storage floors;
- required networks and controller evidence;
- shared cohorts and explicit conflicts;
- reviewed donor sets and fixed semantic adapter names; and
- default and maximum lease durations used only in the displayed plan.

The snapshot defines node envelopes, guest state, ownership, locks, network
and controller evidence, backup observations, existing commitments, and source
timestamps. Unknown fields and malformed or contradictory data are rejected.

### Planner

`plan_start` is a pure function. It first requires the snapshot's
`catalog_digest` to equal the canonical digest of the loaded catalog. It then
checks evidence freshness and skew, inventory and commitment bindings, exact
cohort state, the global exam slot, hard prerequisites, and per-node capacity.

The conservative envelope is:

```text
guaranteed headroom = physical memory
                    - host reserve
                    - running configured maxima
                    - unrealized reservations
                    - requested reserve
```

The diagnostic envelope is:

```text
observed headroom = currently available memory
                  - host reserve
                  - unrealized reservations
                  - requested reserve
```

KSM and swap size are diagnostics and never add allocatable capacity. If only
the observed envelope fits, the result is blocked. Donors may be selected only
from the requested environment's reviewed donor sets. Core-protected,
GPU-affine, locked, unknown, wrong-node, already committed, or backup-unsafe
guests cannot be donors.

Every plan has one outcome:

- `safe_now`
- `safe_with_donors`
- `queued_exclusivity`
- `blocked`
- `unknown`
- `already_active`

Only safe outcomes contain inert action descriptions. Every response carries
the catalog digest, binding digest, snapshot revision, evidence, and a
canonical SHA-256 plan digest.

### One-exam invariant

Every nonterminal exam lease holds one global slot, including activation,
release, and cleanup-failure states. A manually running exam without a valid
lease also blocks another exam. Conflicting live exam commitments make all
plans unknown. Shared cohorts additionally require exact reciprocal ownership
and placement definitions.

### Credential-side collection

`evidence_probe.py` and `live_export.py` are the only modules that read external
state. They run on a trusted collector, not the web host.

The private binding maps public semantic aliases to infrastructure identities.
It must cover every non-template guest exactly once. The probe obtains bounded
read-only evidence for swap configuration, virtual networks, controller state,
bounded backup history, and the optional local exam-status socket. A node with
zero configured swap proves a zero rate; configured swap without a trusted
counter source emits null so plans using that node become unknown. A small
typed protocol permits a deployment-owned counter reader without putting its
transport, credentials, or infrastructure identities in this package. Exact
alias/value/time checks, bounded freshness, and oldest-observation propagation
keep that extension fail closed.

The HTTPS reader issues GET only, ignores proxy configuration, follows no
redirects, verifies TLS unless an explicit test-only escape hatch is selected,
and caps response bytes. Normal API envelopes must contain only `data`. The
exact node task-history and encoded task-log endpoints may additionally contain
an integer `total`; the row count, requested limit, total, and envelope fields
are checked before the list is accepted.

Live evidence embeds the loaded catalog digest. The sanitizer rejects evidence
created for a different catalog, strips source identities, embeds the same
digest in the output snapshot, validates the complete snapshot, and performs a
durable mode-`0600` atomic replacement.

### Application boundary

The application host receives a reviewed catalog and sanitized snapshot only.
`SnapshotFileApplication` reparses the snapshot on every request and rejects a
catalog-digest mismatch. A corrupt, missing, stale, or mismatched snapshot
keeps liveness available but makes readiness and data endpoints fail closed.

The framework-free HTTP server is loopback by default. It limits body and path
sizes, concurrent handlers, and accepted Host values; rejects transfer
encoding, duplicate JSON keys, short bodies, query strings, CORS preflight,
and mutation methods; and serves local assets with a restrictive CSP. Static
reads and GET APIs may be exposed through a separately authenticated TLS
reverse proxy. In-memory `POST /api/v1/plans` is accepted only from a loopback
client and the supplied nginx fragment publishes GET/HEAD only.

Accepted sockets have a ten-second timeout per blocking I/O operation. That is
not a total HTTP-request deadline. The infrastructure response-body reader and
local Unix status client additionally enforce monotonic wall-clock deadlines
for their bounded read loops.

### Dashboard and metrics

The dashboard is a local, accessible operations console. It displays the exam
slot, conservative and observed node envelopes, the environment matrix, donor
impact, hard gates, and immutable evidence digests. It uses `textContent` for
dynamic values and performs GET requests only.

Prometheus output uses only bounded semantic aliases and outcome enums as
labels. Request identifiers and digests are deliberately excluded.

## Data integrity

Canonical objects use a documented integer-oriented, sorted UTF-8 JSON profile
named `broker-cjson-v1`. It is not presented as full RFC 8785. Catalog,
bindings, and plans are independently digested. A catalog change invalidates
previous evidence and snapshots by design.

Files are opened as bounded regular files with symlink and change-during-read
checks. Atomic export uses an exclusive temporary file in the validated target
directory, `fsync`, rename, and directory `fsync`.

## Deployment invariants

- The web identity has no infrastructure token, private binding, status socket,
  database, or command execution capability.
- Source, catalog, static assets, and revision marker are root-owned and not
  writable by the service identity.
- The live service binds to loopback and has systemd filesystem, capability,
  namespace, address-family, process, file-descriptor, task, and memory limits.
- External access requires reviewed TLS and authentication. The provided nginx
  fragment is not a complete server configuration.
- A plan is advice. No component in version 0.1 can apply it.

## Verification

The tests cover strict schemas, capacity arithmetic, multi-node placement,
reservation realization, exclusivity, donor safety, freshness, catalog-digest
pinning, live sanitization, bounded collection contracts, HTTP hardening,
frontend safety, metrics labels, package resources, and public-tree hygiene.
Published JSON Schema documents are validated with a pinned test dependency;
runtime planning remains standard-library only.

Future persistence, approvals, observability, and execution work is separated
in [ROADMAP.md](ROADMAP.md).
