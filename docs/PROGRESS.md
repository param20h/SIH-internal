# TVA build log

Running summary of how this project is being built, phase by phase, per the
build order in the original brief. Updated at the end of each phase. Each
entry records what was built, the real problems found while verifying it
(not just what was planned), any design tradeoff that was decided and why,
and the commit it landed in. Later phases should read this before starting,
especially the "decisions" entries — they explain *why* the code looks the
way it does, not just what it does.

Status at a glance:

| Phase | Name | Status | Commit |
|---|---|---|---|
| 0 | Foundation | done | `505cb1b` |
| 1 | Deterministic forensics engine | done | `efcf26b` |
| 2 | API + persistence | done | `<pending>` |
| 3 | Frontend | not started | — |
| 4 | AI detection layer | not started | — |
| 5 | Attribution & evidence export | not started | — |
| 6 | Demo hardening | not started | — |

---

## Phase 0 — Foundation

**Commit:** `505cb1b`

Scaffolded the monorepo (`backend/ frontend/ ml/ data/ docs/ docker/`),
wired up Docker Compose (postgres, redis, api, worker, web), added a
dependency-aware `/health` endpoint that degrades instead of raising when
postgres/redis are unreachable, configured `ruff` + `mypy --strict` +
`pytest` for the backend and `eslint` + `tsc --strict` for the frontend,
and hand-wrote 20 synthetic `.eml` fixtures in `data/samples/` covering the
forensic edge cases Phase 1 would need (SPF/DKIM/DMARC failures,
display-name and homoglyph spoofing, forged/anomalous relay chains,
base64-hidden payloads, HTML redirect mismatches). See
[`data/samples/README.md`](../data/samples/README.md) for the full list.

**Verified:** `docker compose build` succeeds for all three custom images;
`docker compose up` brings up a fully healthy stack; 44/44 tests pass;
`ruff`/`mypy --strict` clean; frontend renders against the live API in the
browser with no console errors.

**No open design questions** — this phase was mechanical scaffolding.

---

## Phase 1 — Deterministic forensics engine

**Commit:** `efcf26b`

Built the core, zero-ML pipeline in `backend/app/forensics/`:

- `parser.py` — crash-proof `.eml`/`.msg` parsing. Never raises; returns a
  `parse_confidence` score plus a list of recorded issues instead.
- `auth.py` — SPF/DKIM/DMARC verdict extraction, plus DKIM expiry
  detection from the `DKIM-Signature` header's `x=` tag.
- `relay_chain.py` — Received-header parsing and earliest-to-latest chain
  reconstruction, tolerant of real-world MTA header format variance.
- `anomalies.py` — negative time deltas between hops, bogon/private IPs
  crossing an organizational boundary, duplicated/forged relay hosts,
  chain-continuity breaks, hop-count outliers, expired DKIM signatures.
- `geoip.py` / `rdap.py` — local GeoLite2 and opt-in cached RDAP
  enrichment, both degrading gracefully when unavailable.
- `report.py` / `cli.py` — orchestration, and a CLI that prints a full
  forensic report (`--json` for machine-readable) for any sample file.

**Verified:** 121/121 tests pass (unit coverage per module, plus
full-corpus end-to-end assertions against all 20 real Phase 0 samples);
`ruff`/`mypy --strict` clean; the whole 20-file corpus processes in under
4 seconds combined (budget is 10s *per email*).

### Decisions made this phase

**SPF/DKIM/DMARC source of truth is the `Authentication-Results` header,
not live DNS re-validation.** Real DKIM verification is a cryptographic
check against a DNS-published public key; real SPF is a policy check
against DNS state at the moment of delivery. Neither can be meaningfully
redone offline after the fact — and the hard constraint requires this
layer to be 100% reliable with or without connectivity. So the
topmost `Authentication-Results` header (added last, by the boundary MTA
closest to the recipient) is treated as authoritative: pure header logic,
zero network dependency. This matches how most real forensic/security
tools work in practice, since DNS state can change after delivery anyway.
Live re-verification stays a Phase 4+ corroboration signal, not a
replacement.

**Two false positives were found and fixed by testing against the real
corpus, not just by design review:**

1. The "clean" sample emails used RFC 5737 documentation IP ranges
   (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) for legitimate
   infrastructure. Python's `ipaddress` module bundles these into
   `is_private`, so the bogon-IP check was flagging nearly every clean
   sample as suspicious. Fixed by (a) scoping the bogon check to hops that
   cross an organizational boundary — a private IP within one org's own
   infra hopping internally is normal and shouldn't be flagged — and
   (b) explicitly excluding RFC 5737/3849 documentation ranges from the
   bogon definition, since they represent a different category
   ("reserved for writing examples") from "this claims to be on someone's
   private LAN."
2. The anomaly detector originally flagged any Received-header timestamp
   more than 24h ahead of wall-clock "now." This is the wrong model for a
   *forensic* tool: it assumes analysis happens right after delivery,
   which breaks for any historical/cold-case analysis, and it broke
   immediately against the static sample corpus (dated slightly ahead of
   whatever day the corpus happens to be tested on). Removed the
   wall-clock-relative check entirely; kept only the timeless absolute
   sanity bound (nothing predates 1990) and the real signal
   (negative time deltas *between hops in the same chain*, which needs no
   external reference point at all).

**Dev-experience change:** `docker-compose.yml` now also mounts
`backend/tests/` and `backend/pyproject.toml` into the `api`/`worker`
containers (previously only `app/` was mounted), so editing or adding
tests no longer requires an image rebuild to pick them up.

---

## Phase 2 — API + persistence

**Commit:** `<pending>`

Added the REST API and Postgres persistence layer:

- `app/models/analysis.py` — SQLAlchemy models: `Analysis` (normalized
  top-level fields for filtering/stats, plus `meta_json`/
  `authentication_json` JSONB columns for full fidelity), `Hop` and
  `Anomaly` (fully normalized, FK'd to `Analysis`, cascade-deleted with
  it). An IOC table is deliberately not added yet -- see "decisions"
  below.
- `alembic/` — proper migration setup (`env.py` reads the live
  `DATABASE_URL` from `app.core.config`, autogenerate diffs against
  `Base.metadata`). Initial migration generated and applied; `make
  migrate` / `make makemigration m="..."` wrap the common commands.
- `app/crud.py` — the persistence layer bridging `ForensicReport`
  (Phase 1's domain model) and DB rows in both directions:
  `create_completed_analysis` / `complete_analysis` / `fail_analysis` for
  writes, `to_analysis_detail` for the API response shape,
  `to_forensic_report` for reassembling the exact same domain model the
  CLI renders, so a report looks identical whether it was just generated
  or reloaded from the database days later.
- `app/api/analyses.py` — `POST /analyses` (single upload, analyzed
  synchronously -- Phase 1's corpus timing test showed this takes well
  under a second per email), `POST /analyses/batch` (multi-file upload,
  each queued as a Celery job), `GET /analyses` (paginated, filterable by
  status/spf/dkim/dmarc), `GET /analyses/{id}`, and
  `GET /analyses/{id}/export?format=json|txt`.
- `app/api/stats.py` — `GET /stats`: totals, status/spf/dkim/dmarc
  breakdowns, anomaly type/severity breakdowns, last-24h count.
- `app/tasks.py` — the Celery task backing batch uploads; marks the
  placeholder row `failed` with the exception detail rather than losing
  the job if analysis somehow raises (Phase 1's `generate_report` is
  designed never to, but the task layer doesn't get to assume that).
- `app/forensics/render.py` — extracted the CLI's human-readable
  rendering into a shared function so the CLI and the API's `?format=txt`
  export can never drift out of sync with each other.

**Verified:** 147/147 tests pass (added CRUD unit tests, API endpoint
tests via a transactionally-isolated `TestClient`, and a dedicated Celery
task test), `ruff`/`mypy --strict` clean. Also smoke-tested against the
real running stack (not just the test suite): uploaded a sample via curl,
confirmed the DB row and response shape; submitted a two-file batch,
confirmed the worker picked both up from Redis and completed them
asynchronously; confirmed `/stats` aggregates correctly across everything
uploaded so far; confirmed `/docs` (OpenAPI) lists all the new routes.

### Decisions made this phase

**Single upload runs synchronously; only batch uploads go through
Celery.** The brief's own phrasing ("Async job pipeline via Celery for
batch uploads") implies this split, and Phase 1's timing test showed the
whole 20-file corpus processes in under 4 seconds combined -- so making a
single upload wait on a queue round-trip would be slower than just
running it inline, for no benefit.

**Raw email bytes are stored as Postgres `bytea`, not a shared
filesystem path.** Both the `api` and `worker` containers already share
the same Postgres; storing the upload there (not on a separately-mounted
volume) means there's exactly one place a queued job needs to look, no
extra volume wiring, and no cleanup-orphaned-files problem.

**Alembic manages the schema; no `Base.metadata.create_all()` magic in
app startup.** Two sources of truth for schema (an ad-hoc create-all
*and* tracked migrations) invites drift. Alembic was already a listed
dependency, so this is the "boring, proven" choice, not extra scope.
Tests still use `create_all()` in a fixture, but that's a separate,
narrower concern (get *some* schema in place for an ephemeral test run,
optionally without alembic installed in CI) that doesn't conflict with
alembic being authoritative for real deployments.

**No IOC table yet.** The brief lists "analyses, hops, indicators, IOCs"
as what the Phase 2 schema should hold, but nothing before Phase 5 (IOC
extraction: IPs, domains, URLs, attachment SHA256, sender addresses)
populates one. Adding it now would be schema nobody uses -- a violation
of the project's own "don't design for hypothetical future requirements"
engineering rule. Alembic makes adding it later a small, ordinary
migration, not a redesign.

**API tests run against the real Postgres service, not a separate test
database, using per-test transaction rollback for isolation.** Each test
opens its own connection, begins an outer transaction, and binds its
`Session` to that connection with SQLAlchemy 2.0's
`join_transaction_mode="create_savepoint"` -- so even though the CRUD
layer calls `session.commit()` for real (as it does in production), that
only releases a SAVEPOINT; the outer transaction (and everything the test
did) is rolled back at teardown. FastAPI's `get_db` dependency is
overridden per-test to hand out that same session, so `TestClient`
requests hit the isolated transaction too. This avoids standing up a
second database service just for tests while still guaranteeing nothing
a test does ever lands in real dev data. The one exception is
`test_tasks.py`, which tests the Celery task directly: the task opens its
own `SessionLocal()` (a different connection than the test fixture's), so
that test talks to the real database directly and cleans up explicitly
instead.

**Known limitation, noted rather than fixed:** endpoints use a
synchronous SQLAlchemy `Session` called directly from `async def` route
handlers, which blocks the event loop during DB I/O. Acceptable at
hackathon-demo concurrency; a fully async stack (async psycopg +
`AsyncSession`) would be the correct fix for real production load, but is
disproportionate scope for this project's actual requirements right now.
