# Developer entry points.

PYTEST = SCRUTINEERING_TEST_MODE=1 PYTHONPATH=. uv run -q --with-requirements requirements.txt python -m pytest

.PHONY: up down migrate backup test test-python check fmt fmt-check lock smoke e2e record-fixtures

up:
	@# Create the sources folder as you, before Docker creates it as root for the bind mount.
	@dir=$$(sed -n 's/^REMEDIATION_HOST_SOURCES=//p' .env 2>/dev/null | tail -1); \
		mkdir -p "$${dir:-./.local/remediation-sources}"
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
	node scripts/check-python-lock.mjs
	node --test scripts/tests/*.test.mjs

# Formatting and lint; enforced in CI.
fmt-check:
	uvx ruff@0.17.4 format --check src tests scripts
	uvx ruff@0.17.4 check src tests scripts
	cd dashboard && npx --yes prettier@3.3.3 --check "src/**/*.{ts,tsx,css}" "../scripts/**/*.mjs"
	node scripts/check-line-length.mjs

# Apply the formatters.
fmt:
	uvx ruff@0.17.4 format src tests scripts
	uvx ruff@0.17.4 check --fix src tests scripts
	cd dashboard && npx --yes prettier@3.3.3 --write "src/**/*.{ts,tsx,css}" "../scripts/**/*.mjs"

# Regenerate requirements.txt from requirements.in: exact versions with hashes, from releases at least 14 days
# old (docs/design/dependency-pinning.md).
lock:
	cutoff=$$(date -u -d '14 days ago' +%Y-%m-%d 2>/dev/null || date -u -v-14d +%Y-%m-%d); \
		uv pip compile requirements.in --universal --generate-hashes --python-version 3.13 \
		--exclude-newer "$$cutoff" -o requirements.txt

# Requires a running stack (make up).
smoke:
	node scripts/smoke-dashboard.mjs
	node scripts/smoke-live-scan.mjs

# Golden path against the running stack with real scanners (run before merging to main).
e2e:
	python3 scripts/e2e-golden-path.py

# Rebuild the fixture images and re-record the scanner output the golden-path test replays.
record-fixtures:
	scripts/record-golden-fixtures.sh
