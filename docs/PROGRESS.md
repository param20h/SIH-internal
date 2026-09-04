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
| 2 | API + persistence | in progress | — |
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

## Phase 2 — API + persistence (in progress)

Not yet complete — this section is updated when the phase finishes.
