from alembic import context
from sqlalchemy import engine_from_config, pool
from logging.config import fileConfig
from pathlib import Path
import os, sys

# --- Ensure project root is importable ---
BASE_DIR = Path(__file__).resolve().parents[1]  # ~/fintech-core
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

# Alembic Config object
config = context.config

# Safe logging (works even if logging blocks are missing)
if config.config_file_name:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

# ---- Import your SQLAlchemy Base ----
# Try models.py first; if not found, fall back to main.py
try:
    from models import Base
except ModuleNotFoundError:
    from main import Base

target_metadata = Base.metadata

def _db_url():
    return os.getenv("DATABASE_URL", "sqlite:///./bank.db")

def run_migrations_offline():
    context.configure(
        url=_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(
        {"sqlalchemy.url": _db_url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

