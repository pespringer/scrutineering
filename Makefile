# Developer entry points.

PYTEST = SCRUTINEERING_TEST_MODE=1 PYTHONPATH=. uv run -q --with-requirements requirements.txt \
	--with pytest --with httpx python -m pytest

.PHONY: up down migrate backup test test-python check fmt-check smoke

up:
	docker compose up --build -d

down:
	docker compose down

migrate:
	docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade head

# Writes a compressed logical backup of the running database to ./backups/.
backup:
	mkdir -p backups
	docker compose exec -T postgres sh -c 'pg_dump -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" --no-owner' \
		| gzip > backups/scrutineering-$$(date +%Y%m%d-%H%M%S).sql.gz
	@ls -1t backups/*.sql.gz | head -1

test: test-python check

test-python:
	$(PYTEST) tests/ -q

# Repository checks: doc links, deployment manifests, frontend layout.
check:
	node scripts/validate-doc-links.mjs
	node scripts/validate-deployment-config.mjs
	node scripts/validate-frontend-config.mjs
	node --test scripts/tests/*.test.mjs

# Advisory until Phase 3 reformats the codebase.
fmt-check:
	uvx ruff@0.6.9 format --check src tests
	cd dashboard && npx --yes prettier@3.3.3 --check "src/**/*.{ts,tsx,css}"

# Requires a running stack (make up).
smoke:
	node scripts/smoke-dashboard.mjs
	node scripts/smoke-live-scan.mjs
