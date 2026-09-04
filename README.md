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

**Phase 2 — API + persistence.** Phase 0 (monorepo scaffold, Docker Compose
stack, health endpoint, lint/type/test tooling, 20-file synthetic sample
corpus — see [`data/samples/README.md`](data/samples/README.md)) and Phase 1
(the deterministic, zero-ML forensics pipeline in
[`backend/app/forensics/`](backend/app/forensics/): crash-proof .eml/.msg
parsing, SPF/DKIM/DMARC verdict extraction, Received-header relay-chain
reconstruction, and chain-level anomaly detection) are done. Phase 2 adds a
REST API and Postgres persistence on top: upload-and-analyze, batch upload
via a Celery queue, list/filter/get, JSON/text export, and aggregate stats.
Try the CLI directly:

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
