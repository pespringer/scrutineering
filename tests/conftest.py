"""Shared test configuration."""

import os


# Production code refuses implicit database credentials. Tests explicitly opt
# into an in-memory SQLite engine before application modules are imported.
os.environ.setdefault("SCRUTINEERING_TEST_MODE", "1")
