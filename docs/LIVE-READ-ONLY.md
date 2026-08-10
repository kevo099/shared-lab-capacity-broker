# Live read-only deployment handoff

This document describes a reviewable deployment pattern. It does not create a
service, credential, binding, transfer identity, TLS endpoint, or schedule.

```text
trusted collector                              application host

read-only API + private status socket          sanitized snapshot only
              |                                         |
private bindings and probe config                       v
              |                               loopback Python service
validate, sanitize, atomic replace                       |
              |                                         v
restricted one-file transfer                 authenticated TLS GET proxy
```

The application host has no infrastructure credential, raw inventory map,
private status socket, database, mutation adapter, or executor.

## Collector inputs

Keep these inputs root- or collector-owned outside the public checkout:

1. The exact reviewed catalog deployed to the application.
2. `PVE_HOST`, `PVE_RO_TOKEN_ID`, and `PVE_RO_TOKEN_SECRET` for a dedicated
   audit/read-only identity. A partial read-only pair is rejected and generic
   token variables are ignored.
3. A private binding matching
   [`deploy/contracts/live-bindings-schema-v1.json`](../deploy/contracts/live-bindings-schema-v1.json).
4. A private probe configuration matching
   [`deploy/contracts/live-probe-config-schema-v1.json`](../deploy/contracts/live-probe-config-schema-v1.json).

The read-only identity needs only the endpoints used by the release: cluster
and node inventory, node status, virtual-network inventory, bounded backup task
history, and task logs. Grant no mutation privilege.

### Binding shape

```json
{
  "schema_version": 1,
  "canonical_profile": "broker-cjson-v1",
  "nodes": [
    {
      "alias": "node-cobalt",
      "source_node": "replace-with-private-node",
      "host_reserve_bytes": 12884901888
    }
  ],
  "guests": [
    {
      "alias": "fictional-controller",
      "node_alias": "node-cobalt",
      "source_kind": "qemu",
      "source_id": 7001,
      "owner_environments": ["fictional-environment"],
      "core_protected": true,
      "gpu_affine": false
    }
  ]
}
```

This is a shape example, not a valid partial binding. Bound nodes must exactly
cover catalog placements. Every non-template guest returned by the reviewed
cluster must be mapped one-to-one. Cohort members must be on their declared
placement nodes. Inventory-only guests must be core protected. Extra, missing,
duplicated, or moved identities reject the entire export.

### Multi-node placements

The aggregate compatibility fields remain present when a policy declares
explicit placements:

```json
{
  "host_affinity": "node-cobalt",
  "reserved_memory_bytes": 28991029248,
  "minimum_root_free_bytes": 10737418240,
  "cohort": ["member-one", "member-two", "member-three"],
  "placements": [
    {
      "node": "node-cobalt",
      "reserved_memory_bytes": 21474836480,
      "minimum_root_free_bytes": 10737418240,
      "cohort": ["member-one", "member-two"]
    },
    {
      "node": "node-amber",
      "reserved_memory_bytes": 7516192768,
      "minimum_root_free_bytes": 8589934592,
      "cohort": ["member-three"]
    }
  ]
}
```

Placements must partition the exact cohort, use unique nodes, sum to the
aggregate memory reserve, and agree with the aggregate storage floor. The
planner evaluates every node independently. A missing node, misplaced member,
partial commitment, swap violation, or capacity shortfall fails the complete
environment closed.

### Probe configuration shape

```json
{
  "schema_version": 1,
  "task_history_limit": 32,
  "broker_status_socket": "/run/example-collector/status.sock",
  "networks": [
    {"alias": "assessment-fabric", "source_vnet": "replace-with-private-vnet"}
  ],
  "controllers": [
    {
      "alias": "semantic-controller",
      "pve_guest_aliases": ["fictional-controller"],
      "require_exam_broker": false,
      "implemented": true
    },
    {
      "alias": "pending-controller",
      "pve_guest_aliases": [],
      "require_exam_broker": false,
      "implemented": false
    }
  ],
  "backup_maximum_age_seconds": {
    "backup-gated-environment": 64800
  },
  "broker_lab_owners": {
    "broker-lab-a": "cluster-blue"
  }
}
```

Network and controller aliases must exactly cover the catalog. Guest checks use
semantic binding aliases. An unimplemented controller declares no checks and
always emits false. Backup thresholds exactly cover backup-gated environments.
Broker owner values are distinct exam environments.

The broker socket must be absolute, non-symlink, owned by the collector user,
and private to that user. The client sends only `{"action":"status"}`, caps
the response at 8 KiB, and enforces a two-second monotonic wall-clock deadline.
Run the collector under the socket owner or add a separately reviewed relay;
do not loosen the socket mode.

## Evidence guarantees

`probe-evidence` emits the exact schema in
[`deploy/contracts/live-evidence-schema-v1.json`](../deploy/contracts/live-evidence-schema-v1.json).

- Zero swap-in rate is emitted only when node status proves zero configured
  swap. If swap exists and no trusted counter provider is configured, the
  probe emits null. The dashboard remains available, but every plan placed on
  that node becomes `unknown` with no actions.
- A deployment may inject a transport-neutral `SwapRateReader` into
  `probe_live_evidence` or `export_probe_evidence`. The public package ships no
  SSH client, host identity, key path, account, command, or concrete reader.
- Required virtual networks are true only for one exact, non-pending match.
- Controller health is the conjunction of declared running guest checks and,
  when required, broker health. Unimplemented controllers remain false.
- Broker status binds shared-cohort ownership and one semantic exam commitment
  for non-idle phases.
- Backup evidence scans bounded task history. The exact task-list and encoded
  task-log endpoints may return `{data,total}`; `total` must be a strict integer
  consistent with the requested limit and bounded row list, and no extra
  envelope fields are accepted.
- For each member, the newest matching backup attempt must include exact start
  and finish records. Missing, incomplete, ambiguous, future, or over-age
  evidence becomes unknown or stale.
- The evidence includes the canonical digest of the loaded catalog.

Example output:

```json
{
  "schema_version": 1,
  "catalog_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "source_observed_at": {
    "telemetry": "2035-06-15T11:59:50Z",
    "controllers": "2035-06-15T11:59:49Z",
    "backups": "2035-06-15T11:59:48Z"
  },
  "node_swap_in_bytes_per_second": {"node-cobalt": 0},
  "networks": {"assessment-fabric": true},
  "controllers": {"semantic-controller": true},
  "backups": [
    {
      "environment_id": "backup-gated-environment",
      "state": "fresh",
      "age_seconds": 1500
    }
  ],
  "active_owners": {},
  "exam_lease": null
}
```

No raw node, network, guest, task, token, or socket identity is emitted.

### Optional swap-rate reader API

The public extension point is deliberately smaller than any deployment-specific
collector:

```python
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

@dataclass(frozen=True, slots=True)
class SwapRateEvidence:
    observed_at: datetime
    node_swap_in_bytes_per_second: Mapping[str, int | None]

class SwapRateReader(Protocol):
    def read(self) -> SwapRateEvidence: ...

class SwapRateUnavailable(RuntimeError):
    pass
```

An injected sample must exactly cover the bound semantic node aliases. Values
are null or strict nonnegative signed 64-bit integers; booleans are rejected.
The observation must be timezone-aware and no later than the completed PVE
telemetry read. A positive rate for a node whose PVE status proves zero
configured swap is contradictory and rejects the collection. Null remains a
valid per-node result.

A valid sample no older than `max_snapshot_age_seconds` replaces the default
zero/null map. The telemetry timestamp becomes the older of the PVE and swap
observations, so a later PVE read cannot make the counter window look newer.
A sample older than that boundary, or an explicit `SwapRateUnavailable`, is
discarded and the exact PVE-derived defaults remain: zero only for proven zero
configured swap, otherwise null. Malformed, future, or contradictory evidence
is not an availability condition and rejects the collection.

## Freshness, pinning, and atomicity

- Each evidence source is timestamped after its corresponding reads finish.
- Inventory is timestamped after live inventory collection.
- `collected_at` follows collection; `generated_at` follows assembly.
- Future, stale, missing, skewed, or contradictory timestamps produce unknown
  plans with no actions.
- Evidence catalog digest must match the exporter's catalog.
- The exporter embeds the same digest in the sanitized snapshot and validates
  the complete document before a durable mode-`0600` atomic replacement.
- The application checks the snapshot digest against its own catalog on every
  request. Mismatch, corruption, absence, or a non-regular file returns `503`
  for readiness/data while liveness remains available.

`generated_at` means the sanitized document was assembled then; it does not
claim every upstream source was observed then.

## Generic commands

Synthetic mode needs no credential:

```bash
lab-broker serve --bind 127.0.0.1 --port 8087
```

One collector cycle uses deployment-private paths:

```bash
set -a
. /etc/example-collector/read-only.env
set +a

lab-broker probe-evidence \
  --catalog-file /etc/example-collector/catalog.json \
  --bindings-file /etc/example-collector/bindings.json \
  --probe-config-file /etc/example-collector/probe.json \
  --output /run/example-collector/evidence.json \
  --ca-file /etc/example-collector/ca.crt

lab-broker export-live \
  --catalog-file /etc/example-collector/catalog.json \
  --bindings-file /etc/example-collector/bindings.json \
  --evidence-file /run/example-collector/evidence.json \
  --output /var/lib/example-export/live-snapshot.json \
  --ca-file /etc/example-collector/ca.crt
```

`--insecure-tls` is a test-only escape hatch and must not appear in a
production unit. The HTTPS reader is direct, GET-only, proxy-independent,
non-redirecting, size-bounded, and TLS-verifying by default. Its response body
loop uses a monotonic deadline covering the remaining request budget. Earlier
connect/header operations have bounded socket timeouts; the Unix status reader
has its own total deadline.

Application command:

```bash
lab-broker serve \
  --bind 127.0.0.1 \
  --port 8087 \
  --catalog-file /etc/lab-broker/catalog.json \
  --snapshot-file /var/lib/lab-broker/live-snapshot.json
```

Transfer only the sanitized snapshot through an identity restricted to one
staging file, then promote it by rename on the destination filesystem. Do not
use a broad administrative key.

## Application artifact

[`deploy/lab-broker-live.service`](../deploy/lab-broker-live.service) expects:

- a pinned release at `/opt/shared-lab-capacity-broker`;
- its artifact or commit digest in a non-writable `REVISION` file;
- root-owned, service-non-writable source and static assets;
- a root-owned, service-non-writable catalog under `/etc/lab-broker`;
- an unprivileged non-login `lab-broker` user; and
- a root-owned, group-readable mode-`0640` sanitized snapshot.

The unit applies a read-only filesystem view, loopback network policy, empty
capabilities, namespace restrictions, and bounded memory, tasks, descriptors,
start, and stop times.

The nginx fragment must be included only in an existing TLS server. It requires
authentication, publishes GET/HEAD only, strips authorization before proxying,
and preserves the loopback Host. If Basic authentication is used, generate
bcrypt hashes (for example, `htpasswd -B -C 12`), protect the password file,
and rotate credentials.

Define request and connection zones in nginx's `http` context, then apply a low
per-client request rate and small burst to the location. Test normal dashboard
polling, monitoring, and `429` behavior. The fragment intentionally does not
declare global zones because those belong to the enclosing deployment.

## Verification and operator gates

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
python3 scripts/check_public_tree.py .
systemd-analyze verify \
  deploy/lab-broker-live.service \
  deploy/lab-broker-synthetic.service
```

Before exposure, also verify the full nginx configuration, TLS, authentication,
rate limiting, snapshot and catalog ownership, artifact pin, loopback
liveness/readiness, credential absence from the web process, exact current
bindings, collector read-only scope, trustworthy swap/controller/backup
evidence, and restricted transfer. Run shadow mode long enough to investigate
every planner disagreement.
