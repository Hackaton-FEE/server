"""Motor y sesiones SQLAlchemy.

Importar este módulo no abre ninguna conexión. `configure()` se llama desde la
app factory y solo prepara el engine (SQLAlchemy conecta de forma perezosa).
"""

from collections.abc import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from fee_server.core.config import Settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def configure(settings: Settings) -> None:
    """Prepara el engine global a partir de la configuración."""
    global _engine, _SessionLocal

    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    _engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Base de datos no configurada: llama a configure() primero")
    return _engine


def get_session() -> Iterator[Session]:
    """Dependencia FastAPI: una sesión por petición, commit al terminar bien."""
    if _SessionLocal is None:
        raise RuntimeError("Base de datos no configurada: llama a configure() primero")

    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
