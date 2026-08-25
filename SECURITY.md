# Security policy

## Supported release

Version 0.1 is an alpha, read-only planner. Security fixes are applied to the
latest revision only.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/kevo099/shared-lab-capacity-broker/security/advisories/new).
Do not post a credential, private topology, personal data, or a working exploit
in a public issue. Include the affected revision, impact, and a minimal
reproduction using fictional data.

## Trust boundary

Synthetic mode contains no credentials. In live mode, a trusted collector uses
a dedicated read-only identity and private alias map, then emits a strict
sanitized snapshot. The application consumes that snapshot without an
infrastructure credential, raw inventory identifier, private binding, broker
socket, persistence layer, mutation adapter, or executor.

The default bind is loopback. This is not a standalone authenticated Internet
service. Any live path requires a separately reviewed TLS reverse proxy,
authentication, rate limiting, restricted snapshot transfer, and least-
privilege collector policy.

## Defensive properties

- Exact JSON rejects duplicate keys, non-finite values, boolean integers,
  unknown fields, oversized values, and signed-64-bit overflow.
- Catalog digests are pinned in probe evidence and snapshots and are rechecked
  by the exporter, planner, and live application.
- Input loaders require bounded regular files and reject symlinks where the
  platform provides `O_NOFOLLOW`.
- The live exporter requires one-to-one reviewed bindings, strips source
  identities, validates the complete snapshot, and replaces one mode-`0600`
  file durably and atomically.
- The infrastructure transport performs GET only, ignores proxies, follows no
  redirects, verifies TLS by default, and bounds response size and read time.
- Normal API envelopes accept only `data`; the exact node task-history and
  encoded task-log paths may also contain a bounded, consistent integer
  `total`.
- The local status client uses a private same-owner Unix socket, a fixed status
  request, a response cap, and a monotonic wall-clock deadline.
- Configured swap without a trusted counter source emits a nullable rate. The
  dashboard remains available, while plans placed on that node become unknown.
  The optional transport-neutral reader accepts only exact semantic coverage,
  strict bounded rates, and non-future aware timestamps; stale or explicitly
  unavailable samples revert to the same conservative zero/null defaults.
- The planner is a pure function with no I/O or implicit clock.
- Missing, stale, future, skewed, contradictory, or mismatched evidence fails
  closed with no actions.
- Donors and semantic adapters come only from a validated catalog. Plans never
  contain a shell command, source host, URL, or raw inventory ID.
- The HTTP process caps request sizes and handlers, validates Host, rejects
  short bodies, disables CORS, and emits strict browser security headers.
- Plan POST is loopback-only. The reverse-proxy fragment publishes GET/HEAD.
- The UI uses local assets and `textContent`, with no HTML injection sink,
  third-party script, or mutating request.
- Metrics labels are bounded aliases and enums, never request IDs or digests.

Accepted HTTP sockets have a ten-second timeout per blocking I/O operation,
not a total request deadline. The infrastructure body loop and Unix status
client also enforce monotonic total deadlines for their bounded reads.

## Sensitive data

Only fictional manifests belong in this repository. Never commit credentials,
cookies, private keys, secret-bearing environment files, real addresses or
hostnames, raw API responses, private bindings, operator paths, production
thresholds, exam content, grades, or personal data.

Run `python3 scripts/check_public_tree.py .` before publication. A private
literal denylist may be passed with `--denylist`; that file must stay outside
the repository.

## Authentication guidance

The nginx example assumes an existing TLS server. If HTTP Basic authentication
is selected for a small trusted deployment, create hashes with bcrypt (for
example, `htpasswd -B -C 12`), store the password file outside the release tree
with restrictive ownership and mode, and rotate credentials. Do not use Basic
authentication over cleartext HTTP.

Define request and connection zones in nginx's `http` context and apply a low
per-client rate with a small burst to the dashboard location. Size the limit
for polling and monitoring, test `429` behavior, and keep upstream connection,
send, and read timeouts bounded. Authentication and rate limiting complement;
neither replaces network access control.

## Before live exposure

- Pin and verify the release artifact and catalog digest.
- Keep source, catalog, static assets, and revision marker root-owned.
- Use distinct identities for collector, transfer, application, and proxy.
- Prove the collector identity has every required read and no mutation rights.
- Validate TLS, authentication, rate limits, logs, backup evidence, controller
  evidence, snapshot ownership, and fail-closed readiness behavior.
- Run a read-only shadow period and investigate every disagreement.
