import uuid

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


@event.listens_for(Session, "after_begin")
def _apply_tenant(session: Session, transaction, connection) -> None:
    """Cada transacción nueva re-aplica el tenant (set_config(..., is_local=true) muere al commit,
    así no puede 'filtrarse' a otra petición a través del pool de conexiones)."""
    org = session.info.get("org_id")
    if org:
        connection.execute(text("SELECT set_config('app.current_org', :o, true)"), {"o": org})


def set_tenant(db: Session, org_id: uuid.UUID | str) -> None:
    """Fija el tenant para las políticas RLS de Postgres (aislamiento de datos entre organizaciones)."""
    db.info["org_id"] = str(org_id)
    db.execute(text("SELECT set_config('app.current_org', :o, true)"), {"o": str(org_id)})
