# TVA — Threat Variance Authority

_For All Mail. Always._

AI-powered email threat detection, geolocation and forensic intelligence
platform. Built for SIH26106 (AICTE — Cyber Security theme). TVA ingests an
`.eml`/`.msg` file and returns two things: an explainable verdict, and a
forensic dossier tracing where the message actually came from.

## Status

See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the full phase-by-phase build
log — what was built, real bugs found while verifying (not just what was
planned), and every design tradeoff decided along the way.

**All six build phases are complete.** Monorepo + Docker Compose
foundation, the deterministic zero-ML forensics engine in
[`backend/app/forensics/`](backend/app/forensics/), an explainable weighted
risk-scoring engine ([`backend/app/scoring/`](backend/app/scoring/)), a REST
API + Postgres persistence layer, the React/TypeScript web app (upload,
analysis view, relay-path world map, dashboard), content-based AI
signals in [`backend/app/ai/`](backend/app/ai/) — a lookalike/typosquat
domain detector, URL analysis (IP-literal links, anchor-text mismatches,
offline redirect unwrapping), a real fine-tuned DistilBERT phishing
classifier (98%+ held-out F1, exported to ONNX — see
[`ml/README.md`](ml/README.md) for the full methodology and an honest
account of a real overfitting bug found and fixed while building it), and a
DistilGPT-2 perplexity-based AI-text signal, all fused into one explainable
risk score. Attribution and evidence export in
[`backend/app/attribution/`](backend/app/attribution/) adds IOC extraction,
STIX 2.1 and CSV export, a confidence-scored heuristic origin-attribution
engine that explains its own reasoning (and openly caps its confidence when
the relay chain shows signs of tampering), a court-oriented forensic PDF
report (chain of custody, verdict, authentication, attribution, relay
chain, a hand-drawn geolocation map, indicator breakdown, IOCs, analyst
notes), and an editable analyst-notes field surfaced in both the UI and the
PDF. Demo hardening adds one-command sample-corpus seeding (`make demo`),
a verified-offline proof (see below), and [`docs/DEMO.md`](docs/DEMO.md)'s
scripted walkthrough. Train the AI models with:

```bash
docker compose build ml
docker compose run --rm ml python scripts/prepare_data.py
docker compose run --rm ml python scripts/train_phishing_classifier.py
docker compose run --rm ml python scripts/export_ai_text_model.py
```

The app works fully without them too — per the hard offline/zero-model
constraint, every AI signal reports "unavailable" and contributes nothing
to the score until trained, rather than failing.

Open `http://localhost:5173` once the stack is up, or try the CLI directly:

```bash
docker compose run --rm api python -m app.forensics.cli /data/samples/13_forged_received_header_injected.eml
```

Or the API, once the stack is up:

```bash
curl -X POST http://localhost:8000/api/v1/analyses \
  -F "file=@data/samples/13_forged_received_header_injected.eml;type=message/rfc822"
```

Interactive OpenAPI docs are at `http://localhost:8000/docs`. First run the
database migration:

```bash
make migrate
```

## Architecture

| Layer | Stack |
|---|---|
| Backend | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy, PostgreSQL, Celery + Redis |
| ML | PyTorch, HuggingFace Transformers, scikit-learn, ONNX Runtime |
| Frontend | React 18 + TypeScript, Vite, Tailwind CSS, TanStack Query, react-simple-maps, Recharts |
| Parsing | Python stdlib `email`, dkimpy, pyspf, checkdmarc, extract-msg |
| Enrichment | geoip2 + local GeoLite2-City, RDAP |
| Reports | WeasyPrint/ReportLab (PDF) |

The deterministic layer — header parsing, SPF/DKIM/DMARC validation, and
relay-chain reconstruction — is pure logic with zero ML dependency and is the
spine of every verdict. Machine learning is strictly additive on top of it.

## Quickstart

```bash
docker compose up --build
make migrate   # applies the Postgres schema (one-time / after a schema change)
make demo      # optional: seed the full 20-sample corpus for a populated UI
```

- API: http://localhost:8000 (docs at `/docs`, health at `/health`)
- Web: http://localhost:5173

See [`docs/DEMO.md`](docs/DEMO.md) for a scripted 3-minute walkthrough of
the app built on that seeded data.

## Repository layout

```
backend/   FastAPI service, Celery worker, deterministic forensics engine
frontend/  React + TypeScript web app
ml/        Model training and ONNX export pipelines
data/      GeoLite2 database (not committed) and the sample .eml corpus
docs/      Design notes and the demo script
docker/    Shared infra config
```

## Development

```bash
make up             # docker compose up --build
make test           # run the backend test suite inside the api container
make lint           # ruff
make typecheck      # mypy --strict
make migrate        # apply Alembic migrations
make makemigration m="add foo column"   # autogenerate a new migration
make demo           # wipe and re-seed the full sample corpus (idempotent)
```

## Offline operation

TVA is designed to run fully offline after the initial `docker compose
build` pulls images and dependencies. Every real upload path (the web app,
the batch endpoint, and `make demo`) runs with network enrichment disabled
by default — RDAP domain-age lookups return `"unavailable"` rather than
making a live call, and GeoIP enrichment reads only a local GeoLite2
database (see [`data/geoip/README.md`](data/geoip/README.md)) with no
fallback to a network service. No mandatory paid API is required to run an
analysis end to end.

This isn't just a design claim — it's been verified with the network
device removed entirely:

```bash
docker run --rm --network none \
  -v "$(pwd)/data:/data" -v "$(pwd)/backend/app:/app/app" \
  tva-api python -m app.forensics.cli /data/samples/13_forged_received_header_injected.eml
```

This produces a complete report — parsing, SPF/DKIM/DMARC, relay-chain
anomaly detection, risk score, and (if `data/models/` is populated) AI
signals — from a container with zero network access, not just zero
*successful* network calls.

## Limitations

This is a hackathon build, not a hardened production system. Specific,
honest gaps rather than a generic disclaimer:

- **SPF/DKIM/DMARC read the `Authentication-Results` header, not a live
  re-verification.** TVA trusts the verdict the boundary mail server
  already computed at delivery time (see Phase 1's design note in
  [`docs/PROGRESS.md`](docs/PROGRESS.md)) rather than redoing DNS-based
  cryptographic checks itself — the only way this layer can be both
  100% offline-capable and accurate for historical/cold-case analysis.
  A message with no `Authentication-Results` header at all yields
  `"none"`/`"unknown"` results, not a failure.
- **Origin attribution is an explained heuristic, not a certainty.** It
  picks the earliest relay hop reporting a public IP and caps its own
  confidence when specific tamper signals (duplicated hostnames, broken
  hop continuity) are present — but an attacker who avoids those specific
  patterns can still evade it. The tool says so in its own reasoning text
  rather than presenting a bare IP as fact.
- **The phishing classifier is trained on a small, dated, English-language
  corpus** (Nazario phishing + three SpamAssassin ham batches — see
  [`ml/README.md`](ml/README.md) for full methodology and a real
  overfitting bug found and fixed while building it). Its 98%+ held-out
  F1 is measured against that same narrow distribution, not a claim about
  real-world precision/recall against modern, non-English, or
  LLM-generated phishing campaigns.
- **The AI-text perplexity signal is a genuinely weak, single-model
  heuristic** and is weighted lowest in the score for exactly that
  reason — it flags unusually uniform phrasing, nothing more.
- **GeoIP requires an operator to install a licensed
  `GeoLite2-City.mmdb`** (MaxMind's terms don't permit bundling it in the
  repo); without it, hop geolocation and the relay-path map report
  `"unavailable"` rather than guessing.
- **Lookalike-domain and anomaly detection use curated tables, not
  exhaustive ones** — a fixed trusted-brand list, a curated confusables
  table (not the full Unicode confusables.txt), and a specific set of
  named anomaly types. A domain or relay-chain pattern outside those
  tables won't be flagged by that specific detector, though the
  deterministic authentication checks still apply independently.
- **Upload-only ingestion.** TVA analyzes `.eml`/`.msg` files it's given;
  it has no IMAP/Exchange/mailbox connector and doesn't monitor a live
  inbox.
- **Attachments are hashed for IOC purposes, not scanned.** SHA-256 and
  metadata are extracted and exported; attachment *content* isn't
  sandboxed or executed for malware analysis.
- **No authentication or multi-tenancy on the API.** This is a
  single-operator forensic tool as built, not a multi-user SaaS backend.
