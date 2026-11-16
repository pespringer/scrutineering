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
