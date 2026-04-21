from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from config.settings import DATABASE_URL


@contextmanager
def get_db_connection() -> Iterator[psycopg.Connection]:
    if not DATABASE_URL:
        raise psycopg.OperationalError("DATABASE_URL is not set")

    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as connection:
        yield connection
