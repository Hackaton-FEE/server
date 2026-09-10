"""Acceso a datos del módulo OSINT: funciones simples sobre una `Session`.

Ninguna función hace commit; eso lo decide quien abre la sesión.
"""

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from fee_server.db.models import OsintFinding, OsintScan
from fee_server.domain.osint.findings import Finding
from fee_server.util.time import utcnow


def add_scan(session: Session, scan: OsintScan) -> OsintScan:
    session.add(scan)
    session.flush()
    return scan


def get_scan(session: Session, scan_id: str) -> OsintScan | None:
    return session.get(OsintScan, scan_id)


def get_owned_scan(session: Session, scan_id: str, user_id: str) -> OsintScan | None:
    scan = session.get(OsintScan, scan_id)
    if scan is None or scan.user_id != user_id:
        return None
    return scan


def delete_scan(session: Session, scan: OsintScan) -> None:
    session.delete(scan)


def replace_findings(session: Session, scan_id: str, findings: Sequence[Finding]) -> None:
    session.execute(delete(OsintFinding).where(OsintFinding.scan_id == scan_id))
    for finding in findings:
        session.add(
            OsintFinding(
                scan_id=scan_id,
                platform=finding.platform,
                category=finding.category,
                url=finding.url,
                username=finding.username,
                status=finding.status,
                confidence=finding.confidence,
                sources=list(finding.sources),
                details=dict(finding.details),
            )
        )


def list_findings(session: Session, scan_id: str) -> list[OsintFinding]:
    return list(session.scalars(select(OsintFinding).where(OsintFinding.scan_id == scan_id)))


def purge_expired(session: Session) -> int:
    """Marca `EXPIRED` los escaneos vencidos y borra sus hallazgos."""
    now = utcnow()
    expired = session.scalars(
        select(OsintScan).where(
            OsintScan.expires_at < now,
            OsintScan.status != "EXPIRED",
        )
    )
    count = 0
    for scan in expired:
        session.execute(delete(OsintFinding).where(OsintFinding.scan_id == scan.id))
        scan.status = "EXPIRED"
        scan.progress = 100
        count += 1
    session.flush()
    return count
