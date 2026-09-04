# TVA — Threat Variance Authority

_For All Mail. Always._

AI-powered email threat detection, geolocation and forensic intelligence
platform. Built for SIH26106 (AICTE — Cyber Security theme). TVA ingests an
`.eml`/`.msg` file and returns two things: an explainable verdict, and a
forensic dossier tracing where the message actually came from.

## Status

**Phase 0 — Foundation.** Monorepo scaffold, Docker Compose stack, health
endpoint, lint/type/test tooling, and a 20-file synthetic sample corpus. See
[`data/samples/README.md`](data/samples/README.md) for what the corpus
covers.

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
make up          # docker compose up --build
make test        # run the backend test suite inside the api container
make lint        # ruff
make typecheck   # mypy --strict
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
