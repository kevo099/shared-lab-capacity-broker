# Roadmap

This roadmap is not implemented in version 0.1. Each stage requires a separate
threat model, failure drills, and explicit deployment approval.

## Read-only hardening

- Implement and independently review a deployment-specific counter-delta
  reader for nodes with configured swap using the public typed evidence seam.
- Shadow-compare planner decisions with operator decisions over a representative
  period and record unexplained disagreements.
- Add OpenTelemetry traces with bounded attributes and explicit sampling.
- Add authenticated identity and authorization at the application boundary.

## Durable coordination

- Add PostgreSQL migrations and separate read, write, and migration roles.
- Store capacity history, leases, reservations, idempotency keys, and an
  append-only application audit log.
- Enforce the one-exam semaphore and capacity reservations with serializable
  transactions and the database clock.
- Add expiring reservations, cleanup ownership, and crash-safe reconciliation.

## Approval workflow

- Persist an immutable plan with catalog, binding, snapshot, and action digests.
- Require an authenticated human decision bound to the exact plan digest.
- Reject approval after plan expiry or any evidence/catalog change.
- Audit approvals and rejections without storing credentials or raw topology.

## Isolated executor

- Keep execution in a separate service identity and deployment boundary.
- Accept only a persisted, approved operation identifier; never accept a shell
  command, URL, host identifier, or arbitrary arguments from the browser.
- Map semantic operations to fixed, versioned, allowlisted adapters with exact
  argument schemas, preconditions, convergence checks, and compensation.
- Add idempotent retry and unknown-effect reconciliation before enabling a real
  mutation adapter.

## Release gates for mutation

- Restore-tested database backups and documented key rotation.
- Timeout-before-effect, timeout-after-effect, partial convergence, process
  crash, host restart, cleanup failure, and compensation drills.
- Independent security review of every adapter and credential scope.
- An operator-visible kill switch and a read-only degradation mode.
