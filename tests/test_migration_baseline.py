"""The migration chain must build exactly the schema the models describe."""

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from src.db.models import Base

ALEMBIC_INI = Path("src/db/migrations/alembic.ini")


def _sqlite_engine(path: Path) -> sa.Engine:
    """SQLite stand-in for Postgres: register the functions the schema's CHECKs and defaults use."""
    engine = sa.create_engine(f"sqlite:///{path}")

    @sa.event.listens_for(engine, "connect")
    def _register_functions(dbapi_connection, _record):
        dbapi_connection.create_function("char_length", 1, lambda value: len(value) if value is not None else None)
        dbapi_connection.create_function("now", 0, lambda: "1970-01-01 00:00:00")

    return engine


def _run(connection: sa.Connection, action, revision: str) -> None:
    config = Config(str(ALEMBIC_INI))
    config.attributes["connection"] = connection
    action(config, revision)


def test_migrations_have_a_single_head_rooted_at_the_baseline():
    script = ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))
    assert len(script.get_heads()) == 1
    assert [revision.revision for revision in script.walk_revisions()][-1] == "0001_baseline"


def test_upgrade_head_matches_models_and_downgrade_removes_everything(tmp_path):
    engine = _sqlite_engine(tmp_path / "schema.db")
    with engine.begin() as connection:
        _run(connection, command.upgrade, "head")
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    with engine.begin() as connection:
        _run(connection, command.downgrade, "base")
    assert set(sa.inspect(engine).get_table_names()) - {"alembic_version"} == set()


def test_0018_copies_sources_onto_remediations_and_chains_existing_audit_records(tmp_path):
    from datetime import datetime

    from src.db import audit_chain

    tables = Base.metadata.tables
    engine = _sqlite_engine(tmp_path / "backfill.db")
    with engine.begin() as connection:
        _run(connection, command.upgrade, "0017_principals")
        connection.execute(sa.insert(tables["images"]).values(id=1, repo_name="team/app"))
        connection.execute(sa.insert(tables["images"]).values(id=2, repo_name="team/web"))
        connection.execute(
            sa.insert(tables["image_sources"]).values(image_id=1, repository="app", ref="v1", test_command=["true"])
        )
        connection.execute(sa.insert(tables["remediations"]).values(id=10, image_id=1, status="proposed"))
        connection.execute(sa.insert(tables["remediations"]).values(id=11, image_id=2, status="proposed"))
        for n in range(3):
            connection.execute(
                sa.insert(tables["audit_log"]).values(
                    timestamp=datetime(2026, 11, 1, 12, 0, n), event_type="config_changed", detail={"n": n}
                )
            )
        _run(connection, command.upgrade, "0018_security_hardening")

    with engine.connect() as connection:
        sources = dict(connection.execute(sa.text("SELECT id, source FROM remediations ORDER BY id")).all())
        audit = connection.execute(sa.select(tables["audit_log"]).order_by(tables["audit_log"].c.id)).all()
    assert sa.JSON().result_processor(engine.dialect, None)(sources[10]) == {
        "repository": "app",
        "ref": "v1",
        "dockerfile_path": "Dockerfile",
        "build_context": ".",
        "build_args": {},
        "test_command": ["true"],
    }
    assert sources[11] is None
    assert audit_chain.verify(audit) == audit_chain.Verification(True, 3, None)
