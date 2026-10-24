from functools import lru_cache

from psycopg_pool import ConnectionPool

from app.config import get_settings


@lru_cache
def get_pool() -> ConnectionPool:
    """Small pool of autocommit connections to Supabase (session pooler).

    Opening a connection to Supabase takes a few hundred ms, so we reuse them.
    `check` discards connections the pooler closed while they were idle.
    """
    return ConnectionPool(
        get_settings().database_url,
        min_size=1,
        max_size=5,
        kwargs={"autocommit": True},
        check=ConnectionPool.check_connection,
        open=True,
    )
