.PHONY: up down build test lint typecheck logs

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

test:
	docker compose run --rm api pytest -v

lint:
	docker compose run --rm api ruff check .

typecheck:
	docker compose run --rm api mypy app

logs:
	docker compose logs -f
