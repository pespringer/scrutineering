from src.api.readiness import check_database, check_dependencies


class Session:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, query): return 1


def test_database_readiness():
    assert check_database(Session) == {"status": "ready"}


def test_database_readiness_fails_closed():
    class Broken:
        def __enter__(self): raise RuntimeError("database down")
        def __exit__(self, *args): pass
    assert check_database(Broken)["status"] == "not_ready"


def test_dependency_readiness_reports_each_check():
    assert check_dependencies(Session, {"redis": lambda: {"status": "ready"}})["status"] == "ready"
