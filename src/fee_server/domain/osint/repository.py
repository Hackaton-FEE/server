"""Acceso a datos del módulo OSINT: funciones simples sobre una `Session`.

Ninguna función hace commit; eso lo decide quien abre la sesión.
"""

from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from fee_server.db.models import OsintFinding, OsintScan
from fee_server.domain.osint.findings import Finding, project_public_details
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
    """Persiste los hallazgos.

    Único punto del pipeline donde un `Finding` (rico, interno) se convierte
    en fila de BD: aquí se aplica `project_public_details` para que solo lo
    público llegue a disco y, por tanto, a cualquier lectura futura de la API.
    """
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
                details=project_public_details(finding.details),
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
        # La correlación deriva nombres y ubicaciones de los hallazgos; se borra
        # con ellos.
        scan.correlation = None
        count += 1
    session.flush()
    return count
