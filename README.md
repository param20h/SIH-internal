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

**Phase 3 — Frontend.** Phases 0–2 are done: monorepo + Docker Compose
foundation, the deterministic zero-ML forensics engine in
[`backend/app/forensics/`](backend/app/forensics/) (crash-proof .eml/.msg
parsing, SPF/DKIM/DMARC verdict extraction, relay-chain reconstruction and
anomaly detection), an explainable weighted risk-scoring engine
([`backend/app/scoring/`](backend/app/scoring/)), and a REST API + Postgres
persistence layer. Phase 3 adds the React/TypeScript web app: drag-and-drop
or paste-raw-headers upload, an analysis view with a verdict banner,
weighted indicator breakdown ("Miss Minutes"), an offline-bundled relay-path
world map, a raw-header viewer with anomalous lines highlighted, a Nexus
Events list, and a stats dashboard. Open `http://localhost:5173` once the
stack is up, or try the CLI directly:

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
```

- API: http://localhost:8000 (docs at `/docs`, health at `/health`)
- Web: http://localhost:5173

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
```

## Offline operation

TVA is designed to run fully offline after the initial `docker compose
build` pulls images and dependencies. GeoIP enrichment reads a local
GeoLite2 database (see [`data/geoip/README.md`](data/geoip/README.md)); RDAP
lookups degrade to a visible "cached" badge when the network is unavailable.
No mandatory paid API is required to run an analysis end to end.

## Limitations

This is an early-stage hackathon build. See [`docs/`](docs/) as later phases
land for an honest accounting of model precision/recall and known gaps.
