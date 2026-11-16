# Developer entry points. Replaces the root npm scripts removed with the Node
# planner (docs/RESET-PLAN.md, Phase 1a). Phase 1e trims the remaining scripts.

PYTEST = SCRUTINEERING_TEST_MODE=1 PYTHONPATH=. uv run -q --with-requirements requirements.txt \
	--with pytest --with httpx python -m pytest

.PHONY: up down migrate test test-python check fmt-check smoke

up:
	docker compose up --build -d

down:
	docker compose down

migrate:
	docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade head

test: test-python check

test-python:
	$(PYTEST) tests/ -q

# Repository checks: doc links, deployment manifests, frontend layout, release config.
check:
	node scripts/validate-doc-links.mjs
	node scripts/validate-deployment-config.mjs
	node scripts/validate-frontend-config.mjs
	node scripts/validate-release-config.mjs
	node --test scripts/tests/*.test.mjs

# Advisory until Phase 3 reformats the codebase.
fmt-check:
	uvx ruff@0.6.9 format --check src tests
	cd dashboard && npx --yes prettier@3.3.3 --check "src/**/*.{ts,tsx,css}"

# Requires a running stack (make up).
smoke:
	node scripts/smoke-dashboard.mjs
	node scripts/smoke-live-scan.mjs
