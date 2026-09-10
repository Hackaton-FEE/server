"""Modelos ORM de autenticación.

Se usan tipos portables (`String`, `LargeBinary`, `Integer`, `DateTime`) para que
el mismo esquema funcione en SQLite (pruebas) y PostgreSQL (despliegue).

Privacidad: el servidor NO guarda correo, teléfono ni contraseña. Un usuario es
un identificador aleatorio (`handle`) más una o varias llaves públicas.
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import DateTime

from fee_server.db.base import Base
from fee_server.util.time import utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # Identificador WebAuthn (`user.id`); opaco y aleatorio.
    handle: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True, index=True)
    # Etiqueta visible en el gestor de passkeys. Texto libre y opcional.
    label: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_active_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    credentials: Mapped[list["Credential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Credential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # Identificador de la credencial devuelto por el autenticador (bytes crudos).
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, index=True)
    # Llave pública en formato COSE. No es secreta.
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    # Contador anti-clonación. 0 es válido (passkeys sincronizadas).
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="credentials")


class OsintScan(Base):
    """Un escaneo de huella digital de la propia identidad del usuario.

    Privacidad: no se guarda el identificador en claro. Solo una pista corta para
    mostrar en la app (`identifier_hint`) y su `sha256` para detectar repeticiones.
    Cada escaneo caduca (`expires_at`) y una rutina borra sus hallazgos.
    """

    __tablename__ = "osint_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    target_type: Mapped[str] = mapped_column(String(16))
    identifier_hint: Mapped[str] = mapped_column(String(32), default="")
    identifier_sha256: Mapped[str] = mapped_column(String(64))
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    exposure_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Por motor: {"status": "...", "started_at": "...", "finished_at": "...",
    #             "error_category": "..."}.
    engines: Mapped[dict] = mapped_column(JSON, default=dict)
    # Capa de correlación (grafo de identidad, timeline, contactos reconstruidos);
    # se calcula al completar el escaneo. Ver `domain/osint/correlation.py`.
    correlation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list["OsintFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class OsintFinding(Base):
    """Una cuenta o presencia detectada por uno o varios motores, ya normalizada."""

    __tablename__ = "osint_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("osint_scans.id", ondelete="CASCADE"), index=True
    )
    platform: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(32), default="other")
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[OsintScan] = relationship(back_populates="findings")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # Solo se guarda sha256(token); el valor en claro se entrega una vez.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
