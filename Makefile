.PHONY: up down build test lint typecheck logs migrate makemigration

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

migrate:
	docker compose run --rm api alembic upgrade head

makemigration:
	docker compose run --rm api alembic revision --autogenerate -m "$(m)"

logs:
	docker compose logs -f
