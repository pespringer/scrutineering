import pytest
from src.db.pool_config import load_pool_config


def test_pool_config_is_bounded():
    assert load_pool_config({"DB_POOL_SIZE": "4", "DB_MAX_OVERFLOW": "2"}) == {"pool_size": 4, "max_overflow": 2}
    with pytest.raises(ValueError): load_pool_config({"DB_POOL_SIZE": "101"})
