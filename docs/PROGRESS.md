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
| 2 | API + persistence | done | `a5bb0d0` |
| 3 | Frontend | done | `5e3346c`, `698c360` |
| 4 | AI detection layer | done | `a049863` |
| 5 | Attribution & evidence export | done | `<pending>` |
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

**Commit:** `a5bb0d0`

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

### A real bug the transactional test setup caught

After the phase's initial commit, running the test suite a second time
(after having manually smoke-tested the live API with curl, which left a
few real rows in the dev database) surfaced two failures:
`test_list_analyses_pagination` and a stats test that wrongly assumed an
empty database. The stats one was a bad test assumption (fixed by
asserting structural invariants instead of exact-zero counts — see
`test_stats_response_shape_and_invariants`), but the pagination failure
was a genuine bug: `list_analyses` sorted only by `created_at DESC`, and
Postgres's `now()` is fixed for the lifetime of a transaction, so several
rows inserted in one transaction (a batch upload, or several rows created
in one test) get an *identical* `created_at`. Without a tiebreaker,
`LIMIT`/`OFFSET` pages over tied rows aren't guaranteed stable, so
consecutive pages could return an overlapping row. Fixed by adding `id`
as a secondary sort key. Worth calling out because it's exactly the kind
of bug that a from-empty test database would never have caught — it only
showed up once real, timestamp-colliding data existed to sort over.

---

## Phase 3 — Frontend

**Commit:** `5e3346c` (backend scoring engine, built first — see below), then
`698c360` (frontend UI).

### Backend portion: the scoring engine

Phase 3's UI spec calls for a "verdict banner with 0-100 risk score" and
an "indicator breakdown panel (each row = name, weight, evidence
snippet)" — but no risk score existed yet; that was formally Phase 4's
job ("fuse all signals into the explainable weighted risk score").
Building the frontend first would have meant either faking a number or
shipping a banner with nothing to show. Since the project's hard
constraint #3 ("every verdict must be EXPLAINABLE... each contributing
indicator shows its name, weight, and evidence") isn't phase-scoped —
it's a standing requirement — a small scoring engine was built first:

- `app/scoring/weights.yaml` — the actual weight config (a real YAML
  file, not a hardcoded dict), covering SPF/DKIM/DMARC results and
  relay-chain anomaly severities. Every weight in it becomes a named
  `ScoreFactor` in the API response with its evidence attached.
- `app/scoring/engine.py` — `compute_risk_score(authentication,
  anomalies) -> RiskScore`, a pure function summing weighted factors,
  clamping to 0-100, and mapping to a `clean`/`suspicious`/`malicious`
  verdict via configurable thresholds.
- Wired into `generate_report()` (so `risk` is now a required field on
  `ForensicReport`), into the DB schema (`risk_score`/`verdict` columns,
  migration `e6db82b15a7e`), and into every response shape (API detail,
  CLI/text export, JSON export).

This is deliberately **not** a placeholder to be thrown away in Phase 4.
Only Phase 1's deterministic signals feed it today; Phase 4 adds the
ML-derived signals (phishing classifier, lookalike-domain, AI-text
detection, URL analysis) into this same weighted-sum framework as
additional config entries, not a replacement for it.

**A calibration gap found by actually running the numbers, not just by
design review:** the first weight pass scored sample 20 (full SPF+DKIM+
DMARC failure against a published `p=reject` policy — deliberately built
as the corpus's clearest-cut "should never reach an inbox" case) at only
55/100, landing in "suspicious" rather than "malicious." A full triple
auth failure against a reject policy essentially never happens for
legitimate mail and is the strongest signal this deterministic-only
layer can produce before Phase 4 adds more — so the weights were
recalibrated (SPF/DKIM fail 15→20, DMARC-fail-by-policy 8/15/25→10/20/35)
so that combination clears the "malicious" threshold on its own (scores
75). Verified across the corpus via the CLI: clean mail scores 0, a
single strong signal (DMARC fail on a reject-policy spoofed-bank sample)
lands at 63/"suspicious", and both full-failure samples land at
75-83/"malicious".

**Verified:** 157/157 tests pass (10 new scoring-engine unit tests
including one that explicitly guards against double-counting the expired
DKIM signal, plus corpus assertions), `ruff`/`mypy --strict` clean.

### Decisions made this phase (backend portion)

**The risk breakdown isn't persisted as its own column/blob.** `risk_score`
and `verdict` are normalized `Analysis` columns (needed for filtering and
stats), but the full explainable factor list is recomputed on read from
`authentication_json` + the `anomalies` table via `compute_risk_score()`
rather than stored a second time. It's a pure function of data already
persisted, so storing it again would just be a second copy that could
drift out of sync -- recomputing costs nothing measurable and is
guaranteed correct by construction.

**The migration backfills existing rows with `server_default`, not a
bare `NOT NULL`.** Autogenerate produced a `NOT NULL` column with no
default, which fails against a table that already has rows (my dev
database did, from Phase 2's live smoke-testing). Added
`server_default='0'` / `'clean'` by hand -- existing pre-scoring rows get
scored 0/"clean" until re-analyzed, which is honest: there's no basis to
claim anything else for data that predates the column.

### Frontend portion

Built out `frontend/src/`: a typed API client (`lib/types.ts` mirrors the
backend Pydantic schemas field-for-field, `lib/api.ts` wraps every
endpoint), hand-rolled shadcn-style UI primitives (`components/ui/` --
Badge/Card/Button/Spinner built directly rather than via the shadcn CLI,
which needs interactive prompts this environment can't drive), and four
routes: Upload (drag-and-drop plus a paste-raw-headers mode -- pasted
text becomes a `File` blob and goes through the exact same upload
endpoint as a real `.eml`), the Nexus Events list, the Analysis detail
page, and the Dashboard.

The analysis page composes: a verdict banner with an animated SVG radial
gauge for the 0-100 score; the "Miss Minutes" indicator panel (product
in-joke, subtle per the style brief) listing every `ScoreFactor` with its
weight and expandable evidence, plus a full anomaly list below it so
even zero-weight (`info` severity) findings stay visible; a relay-path
world map; a hop table; and a raw-header viewer.

**The map ("the money shot") needed real work to stay offline-compliant.**
`react-simple-maps`' own docs default to fetching world topology from a
CDN URL at runtime -- a hard violation of the offline-operation
constraint. Used the `world-atlas` npm package instead (plain topojson
data, `import ... from "world-atlas/countries-110m.json?url"`), which
Vite bundles as a same-origin static asset at build time. No external
network call happens at runtime; a viewer with no internet gets the same
map a viewer with internet does.

**The map degrades honestly when GeoIP data is absent, which it is by
default.** No GeoLite2-City.mmdb license was available in this session
(that requires the user's own free MaxMind account -- see
`data/geoip/README.md`), so every hop in the corpus shows
`enrichment_source: "unavailable"` and the map renders an explicit empty
state explaining why, rather than silently showing nothing or, worse,
fabricating coordinates. The relay chain itself (hop table, anomaly
detection) is unaffected and fully populated regardless -- geolocation is
enrichment, not something the deterministic analysis depends on. This was
verified live in the browser, not assumed.

**The raw-header viewer fetches the actual original bytes, not a
reconstruction.** Initially planned to rebuild a synthetic header block
from already-exposed fields (hop raw headers, Authentication-Results),
but the DB already stores the complete original upload
(`Analysis.raw_bytes`) and nothing exposed it. Extended the export
endpoint with `format=eml` (returns the original bytes verbatim,
available regardless of analysis status since raw bytes exist before
analysis even runs, unlike `json`/`txt` which need a finished
`ForensicReport`) rather than have the UI show an approximation of the
source when the real thing was one small backend change away.

**No frontend test framework was added this phase.** Phase 0's scaffold
didn't set one up (no vitest/jest in devDependencies), and adding one
plus writing meaningful component tests would have been substantial
additional scope for a phase already large enough to need a backend
addition first. Verification instead leaned on live, real-backend
browser testing via the Claude Browser tool -- upload flows exercised
end to end, DOM inspection to confirm computed classes/highlighting
logic, and API responses cross-checked against on-screen numbers. This
is a real gap (regressions in component logic won't be caught
automatically) worth closing in a later pass, not a decision to leave
permanently unaddressed.

**Two real bugs found by that live verification, not by code review:**

1. Phase 0's `eslint.config.js` had no browser globals configured. Flat
   ESLint config (ESLint 9+) dropped the old `env: browser` shorthand --
   globals like `window`, `fetch`, `File`, `HTMLElement` must be listed
   explicitly via the `globals` package. Every browser-touching file in
   this phase failed lint with `no-undef` until fixed. This was a latent
   gap in Phase 0's scaffold that simply hadn't been exercised yet (Phase
   0's only component barely touched the DOM).
2. Recharts' `Pie` (and, less consistently, `Bar`) rendered zero visible
   shapes in the Dashboard despite correct data flowing in with no
   console errors -- a known interaction between Recharts' mount
   animation (built on `react-smooth`) and React 18 `StrictMode`'s
   double-invoked effects in development, where the animation's internal
   state machine can get stuck at its 0% frame. Confirmed by direct DOM
   inspection (`.recharts-pie-sector` count was 0 with valid data
   present) rather than guessing from the screenshot alone. Fixed with
   `isAnimationActive={false}` on both chart types. Instant, non-animated
   chart rendering is arguably the better choice for a dashboard anyway.

**Verified live against the running stack**, not just typecheck/lint:
uploaded via the paste-headers flow, confirmed the verdict banner,
indicator panel weights/evidence, hop table, and raw-header highlighting
(DOM-inspected the exact set of highlighted header blocks -- all three
anomalous `Received:` blocks plus the failing `Authentication-Results:`
block, and nothing else) all matched the underlying data exactly;
confirmed the Nexus Events list and Dashboard (KPI cards, verdict pie,
auth-failure bars, anomaly-type bars) against live `/api/v1/stats`
output. `tsc --noEmit` and `eslint .` both clean; backend suite still
159/159 (2 new tests for the `format=eml` export path), `ruff`/`mypy
--strict` clean.

---

## Phase 4 — AI detection layer

**Commit:** `a049863`

Built all four sub-systems the brief specifies, plus fused them into the
existing weighted risk score:

- **Lookalike-domain detector** (`app/ai/lookalike_domain.py`) — four
  independent, fully offline signals against a configurable trusted-brand
  list ("the Sacred Timeline", `app/ai/trusted_brands.yaml`): homoglyph
  skeleton matching (`app/ai/confusables.py`, a curated Cyrillic/Greek/
  digit confusables table -- not the full Unicode confusables.txt, which
  would catalogue thousands of code points this product never needs to
  reason about), Levenshtein distance, Jaro-Winkler similarity, and
  punycode/IDN decoding.
- **URL analysis** (`app/ai/url_analysis.py`) — extracts links from HTML
  (BeautifulSoup) and plain text, flags IP-literal hosts and anchor-text/
  href mismatches, and unwraps redirect-parameter targets that are
  base64- or URL-encoded directly in the link (offline; never follows a
  live HTTP redirect, which would be a network call on the critical
  path).
- **Phishing classifier** — real DistilBERT fine-tune, real data, real
  ONNX export, real held-out metrics; see `ml/README.md` for the full
  methodology and two real bugs found while building it (below).
- **AI-generated-text scoring** — DistilGPT-2 exported to ONNX,
  perplexity via one teacher-forced forward pass; deliberately the
  lowest-weighted signal in the whole scoring config, because the
  technique is genuinely weak and the module says so everywhere it
  surfaces.
- **Fusion**: `compute_risk_score()` now takes an optional `AiSignals`
  argument; every Phase 4 finding becomes a `ScoreFactor` in the same
  explainable weighted sum Phase 3 built, not a separate score bolted on
  next to it. Weights live in `app/scoring/weights.yaml` alongside the
  Phase 1-3 ones.

**Verified live, not just in tests**: uploaded
`09_homoglyph_domain_paypal.eml` (a phishing email with fully *passing*
SPF/DKIM/DMARC -- would have scored 0/"clean" under Phase 1-3 alone)
through the running app. Phase 4 correctly scored it 57/"suspicious":
+25 phishing classifier, +20 sender-domain lookalike (paypaI.com →
paypal.com, Levenshtein), +12 link-domain lookalike -- every point
traceable to named, evidenced factors on screen, exactly per hard
constraint #3. 203/203 backend tests pass, `ruff`/`mypy --strict` clean,
frontend `tsc`/`eslint` clean.

### Two real bugs in the ML pipeline, found by testing generalization

The full account is in `ml/README.md`; the short version: a first-pass
phishing classifier scored 98%+ on its own held-out test split, then
classified an ordinary hand-written business email as 99.8% phishing --
and, wired into the live pipeline, broke a Phase 1-3 test expecting a
clean sample to score 0. Root cause: 394 ham examples from a single
narrow 2003 mailing-list archive taught the model that batch's stylistic
fingerprint, not real phishing-vs-legitimate semantics. Fixed by sampling
ham from three separate SpamAssassin batches instead of one; the held-out
metrics barely moved (which is the point -- a held-out split of the same
narrow source was never going to catch this), but the hand-written test
sentence went from 99.8% phishing to 7.3%, and 18/20 of TVA's own sample
corpus now match their intended ground truth by content alone (the two
misses are messages whose malicious signal lives entirely in headers/
relay-chain data that the deterministic layer already catches
independently -- defense in depth, not a classifier failure).

Separately, `torch.onnx.export(model, (input_ids, attention_mask), ...)`
silently misaligned arguments for `GPT2LMHeadModel`: a newer
`transformers` version moved `past_key_values` ahead of `attention_mask`
in the positional argument order, so the plain positional tuple bound to
the wrong parameters and the traced export computed something other than
intended (surfaced as an `AttributeError` deep in KV-cache handling code
at export time, not as a silently-wrong model). Fixed in both export
scripts with a small wrapper module that binds inputs by keyword
explicitly -- version-proof against future argument reordering.

### Decisions made this phase

**The DistilBERT/DistilGPT-2 training and export machinery lives in
`ml/`, entirely separate from the backend.** The backend imports
`onnxruntime` + `tokenizers` only -- never `torch`/`transformers` at
runtime -- keeping the `api`/`worker` images free of a multi-hundred-MB
ML framework they don't need for inference. `ml/` gets its own
Dockerfile and a `profiles: ["ml"]` compose service so it never starts
with the normal stack; training is a one-time offline step, not part of
the running application.

**`DomainIntel` moved from `forensics/models.py` to `forensics/rdap.py`.**
`app.ai.url_analysis` needs `DomainIntel` for its per-link domain-age
field, and `forensics.models.ForensicReport` needs to import
`app.ai.models.AiSignals` for its new `ai_signals` field -- those two
facts together would have created a circular import
(`forensics.models` → `ai.models` → `ai.url_analysis` → `forensics.models`)
if `DomainIntel` had stayed put. Moved it to `rdap.py` (where it's
actually produced) and re-exported it from `forensics.models` for every
existing caller, so nothing else had to change.

**The risk-breakdown recomputation pattern from Phase 3 extends to AI
signals too.** `ai_signals_json` is a new nullable JSONB column (nullable
because rows analyzed before this phase predate the whole feature, not
because it's optional going forward), but the full factor list is still
never persisted twice -- `compute_risk_score()` takes the reconstructed
`AiSignals` alongside authentication and anomalies, same as Phase 3's
`risk_score`/`verdict` pattern.

**A stale test bound, not a real performance regression.** The Phase 1
timing test asserted "20 files combined under 10s" -- already stricter
than the actual hard constraint ("under 10s *per email*"). Loading two
ONNX models (one ~268MB) for the first time in a fresh test process adds
a real, one-time deserialization cost that made the combined-20-files
number cross 10s. Fixed the test to warm the model cache before timing
(the `app.ai.pipeline` singletons mean later calls never pay that cost
again) and assert on true per-email average -- which stays well under a
second, nowhere near the actual 10s/email budget.

## Phase 5 — Attribution & evidence export

**Commit:** `<pending>`

Built the four sub-systems the brief specifies for this phase:

- **IOC extraction** (`app/attribution/ioc.py`) — walks a completed
  `ForensicReport` and pulls out every indicator with forensic value: the
  sender email, every relay hop's source IP and claimed hostname, every
  attachment's SHA-256, and every extracted URL's raw form, host, and
  unwrapped redirect target. Deduplicated on `(type, value)`, and each
  entry carries a human-readable `context` string explaining where it was
  found -- an IOC list with no provenance is much less useful in an
  incident-response workflow. Deliberately does *not* try to filter out
  "our own" mail infrastructure hostnames -- there's no reliable generic
  way to know which hop hostnames belong to the recipient's own mail
  system versus the attacker's, so all of them are surfaced and the
  analyst judges.
- **STIX 2.1 export** (`app/attribution/export.py`) — hand-rolled bundle
  generation (`indicator--<uuid>` SDOs with a `pattern`/`pattern_type:
  "stix"` per IOC type), not the `stix2` library. The bundle shape STIX
  2.1 needs for a simple indicator list is small and fully specified;
  pulling in a library (and its schema-validation machinery) for six
  pattern templates was more dependency than the problem justified.
- **Plain CSV export** — same IOC list, `type,value,context` columns, for
  tooling that doesn't speak STIX.
- **Origin attribution** (`app/attribution/origin.py`) — a confidence-
  scored *heuristic*, not a claim of certainty: it picks the earliest hop
  in the relay chain reporting a public, non-bogon source IP, then caps
  confidence at `"low"` if any relay-chain-tampering anomaly
  (`forged_internal_origin`, `negative_time_delta`) affects that hop or
  an earlier one -- because a tampered chain means the "earliest public
  hop" itself could be a forged claim, not the true origin. Confidence is
  `"high"` only when GeoIP/ASN enrichment succeeded and there's no
  forgery signal, `"medium"` with no forgery signal but no enrichment,
  and the reasoning text always explains which of these applied and why,
  plus whether SPF corroborates or contradicts the candidate IP.
- **Forensic PDF report** (`app/attribution/pdf_report.py`) — ReportLab
  (not WeasyPrint: pure-Python, no Pango/Cairo/GDK-Pixbuf system
  dependencies to bundle for offline operation). Chain of custody
  (original filename, SHA-256, parse confidence), verdict, authentication
  table, origin attribution, relay chain table, a hand-drawn lat/long
  "map snapshot" (ReportLab's own `Drawing`/`Circle`/`Line`/`String`
  primitives, not matplotlib -- red markers for bogon hops, blue for
  others, connecting lines in hop order) that honestly reports "No hop
  geolocation available" when GeoIP data isn't present rather than
  drawing an empty or misleading map, the full indicator breakdown, the
  IOC table, and analyst notes.

Also added an editable `analyst_notes` field on each analysis (new
nullable `TEXT` column, PATCH `/analyses/{id}/notes` endpoint) -- a real
casework flow needs a place for a human analyst's own findings alongside
the machine-generated evidence, and it shows up in both the UI and the
PDF report.

**Verified live, not just in tests**: ran the actual Docker Compose stack,
uploaded `13_forged_received_header_injected.eml`, and exercised every new
endpoint against the real running app: `GET .../export?format=pdf`
returned a valid 2-page, 6895-byte PDF with correct chain-of-custody,
verdict, attribution, relay-chain, indicator, and IOC sections;
`?format=stix` returned a well-formed bundle with correct
`[email-addr:value = 'security@example-corp.test']`-style patterns;
`?format=ioc-csv` returned correct rows; `GET .../iocs` returned
`{"case_id":"TVA-80CA680C","iocs":[...]}`; `PATCH .../notes` saved
analyst text and returned it in the full `AnalysisDetail` payload.
Frontend: added `AttributionPanel`, `IocTable` (with STIX/CSV export
buttons), and `AnalystNotes` (editable, autosaves via `PATCH`) components,
wired into `AnalysisPage.tsx` alongside a new "Forensic PDF report"
export button; confirmed all three render correctly against the live
analysis above (attribution reasoning text, all 9 extracted IOCs, working
notes counter) via the running dev server. 230/230 backend tests pass (27
new), `ruff`/`mypy --strict` clean, frontend `tsc`/`eslint` clean.

### Decisions made this phase

**`OriginAttribution`/`AttributionConfidence` are defined directly in
`forensics/models.py`, not in `app/attribution/origin.py` where they're
produced.** Same class of circular-import problem as Phase 4's
`DomainIntel`: `forensics.models.ForensicReport` needs `OriginAttribution`
for its new `attribution` field, and `attribute_origin()` needs
`RelayHop`/`Anomaly`/`AuthResult` from `forensics.models` to do its job.
Unlike `DomainIntel`, `origin.py` is tightly coupled to those core
forensic types -- it walks the relay chain directly -- so it couldn't
become the "more foundational" module the way `rdap.py` could. Defining
the output type in `forensics.models` instead keeps the dependency
one-directional (`attribution` → `forensics.models`, never back), and the
class docstring records this precedent for whichever future module hits
the same shape of problem.

**STIX and CSV export are hand-rolled, not built on the `stix2`
library.** A STIX 2.1 indicator bundle for six flat IOC types is a small,
fully-specified JSON shape; the `stix2` library's main value (schema
validation, typed SDO construction, relationship graphs) buys little here
and adds a dependency whose transitive footprint isn't worth it for what
amounts to six string templates.

**`case_id` is derived from the analysis UUID (`TVA-<first 8 hex chars,
uppercase>`), never stored as its own column.** It's used consistently
across the PDF, STIX bundle, and IOC endpoint, but computing it in
`crud.case_id_for()` means it can never drift out of sync with the row it
names, and there's no migration or backfill question for existing rows.

**Origin attribution is explicitly a `"heuristic"` source, not a
`"confirmed"` one, and confidence is capped downward rather than computed
as a positive score.** A forensic tool that presents "high confidence"
by default and only reluctantly admits uncertainty would be actively
misleading in exactly the tampered-header cases where attribution matters
most -- so the design starts from "how much reason is there to doubt this
candidate" and only reaches `"high"` when nothing found a reason to
doubt it *and* independent enrichment corroborates it.
