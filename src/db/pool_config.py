def load_pool_config(env: dict[str, str] | None = None) -> dict[str, int]:
    values = env or {}
    def integer(name, default, maximum):
        value = int(values.get(name, default))
        if value < 1 or value > maximum: raise ValueError(f"{name} is out of range")
        return value
    return {"pool_size": integer("DB_POOL_SIZE", 20, 100), "max_overflow": integer("DB_MAX_OVERFLOW", 10, 100)}
