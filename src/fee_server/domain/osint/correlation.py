"""Capa de correlación: cruza los `Finding[]` ya deduplicados para producir
señales densas para el dashboard, sin red ni dependencias nuevas.

Tres señales (ver `docs/osint-architecture.md` §9.5):

- **Grafo de identidad**: cuentas ligadas a la misma persona por evidencia
  compartida (nombre real, ubicación, empresa, alias) y sus clústeres.
- **Timeline de antigüedad**: línea temporal a partir de `creation_date`.
- **Contactos reconstruidos**: agrupa los `masked_email` / `masked_phone` que
  varios sitios exponen y los contrasta con el correo aportado por el usuario.

Funciones puras y deterministas: cada paso devuelve estructuras nuevas y nunca
muta las anteriores (regla de inmutabilidad del proyecto). Este módulo no
registra nada; solo transforma.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from fee_server.domain.osint.findings import CONFIRMED, Finding
from fee_server.util.time import as_utc, utcnow

# Atributos de `details` que, compartidos entre dos cuentas, prueban que
# pertenecen a la misma persona. `username` se compara aparte (campo propio).
_LINKING_KEYS: tuple[str, ...] = ("full_name", "location", "company")
_DAYS_PER_YEAR = 365.25
# Una cuenta creada hace más de estos años es riesgo latente: superficie antigua
# que el usuario probablemente ya no vigila. (Sin señal de última actividad
# todavía; ver docs/osint-architecture.md §9.5.)
_DORMANT_YEARS = 5


# --- Estructuras de salida ------------------------------------------------


@dataclass(frozen=True, slots=True)
class IdentityNode:
    id: str
    platform: str
    username: str | None
    category: str


@dataclass(frozen=True, slots=True)
class IdentityEdge:
    source: str
    target: str
    shared: tuple[str, ...]

    @property
    def weight(self) -> int:
        return len(self.shared)


@dataclass(frozen=True, slots=True)
class IdentityGraph:
    nodes: tuple[IdentityNode, ...] = ()
    edges: tuple[IdentityEdge, ...] = ()
    clusters: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    platform: str
    username: str | None
    created_at: str
    age_years: float


@dataclass(frozen=True, slots=True)
class Timeline:
    entries: tuple[TimelineEntry, ...] = ()
    oldest_platform: str | None = None
    oldest_date: str | None = None
    newest_platform: str | None = None
    newest_date: str | None = None
    span_years: float = 0.0
    dormant_old_accounts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReconstructedContact:
    kind: str  # "email" | "phone"
    pattern: str
    sources: tuple[str, ...]
    count: int
    consistent_with_provided: bool | None = None


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    identity_graph: IdentityGraph = field(default_factory=IdentityGraph)
    timeline: Timeline = field(default_factory=Timeline)
    reconstructed_contacts: tuple[ReconstructedContact, ...] = ()

    def to_dict(self) -> dict:
        return {
            "identity_graph": {
                "nodes": [
                    {
                        "id": n.id,
                        "platform": n.platform,
                        "username": n.username,
                        "category": n.category,
                    }
                    for n in self.identity_graph.nodes
                ],
                "edges": [
                    {
                        "source": e.source,
                        "target": e.target,
                        "shared": list(e.shared),
                        "weight": e.weight,
                    }
                    for e in self.identity_graph.edges
                ],
                "clusters": [list(c) for c in self.identity_graph.clusters],
            },
            "timeline": {
                "entries": [
                    {
                        "platform": t.platform,
                        "username": t.username,
                        "created_at": t.created_at,
                        "age_years": t.age_years,
                    }
                    for t in self.timeline.entries
                ],
                "oldest_platform": self.timeline.oldest_platform,
                "oldest_date": self.timeline.oldest_date,
                "newest_platform": self.timeline.newest_platform,
                "newest_date": self.timeline.newest_date,
                "span_years": self.timeline.span_years,
                "dormant_old_accounts": list(self.timeline.dormant_old_accounts),
            },
            "reconstructed_contacts": [
                {
                    "kind": c.kind,
                    "pattern": c.pattern,
                    "sources": list(c.sources),
                    "count": c.count,
                    "consistent_with_provided": c.consistent_with_provided,
                }
                for c in self.reconstructed_contacts
            ],
        }


# --- Grafo de identidad -------------------------------------------------


def _node_id(finding: Finding) -> str:
    return f"{finding.platform}:{finding.username or ''}"


def _linking_values(finding: Finding) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in _LINKING_KEYS:
        raw = finding.details.get(key)
        if isinstance(raw, str) and raw.strip():
            values[key] = raw.strip().casefold()
    if finding.username and finding.username.strip():
        values["username"] = finding.username.strip().casefold()
    return values


def _shared_keys(a: dict[str, str], b: dict[str, str]) -> tuple[str, ...]:
    return tuple(sorted(key for key in a if key in b and a[key] == b[key]))


class _UnionFind:
    def __init__(self, items: Sequence[str]) -> None:
        self._parent = {item: item for item in items}

    def find(self, item: str) -> str:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        self._parent[self.find(a)] = self.find(b)

    def clusters(self) -> list[tuple[str, ...]]:
        groups: dict[str, list[str]] = {}
        for item in self._parent:
            groups.setdefault(self.find(item), []).append(item)
        return [tuple(sorted(members)) for members in groups.values() if len(members) > 1]


def build_identity_graph(findings: Sequence[Finding]) -> IdentityGraph:
    confirmed = [f for f in findings if f.status == CONFIRMED and f.username]
    if not confirmed:
        return IdentityGraph()

    nodes = tuple(
        IdentityNode(_node_id(f), f.platform, f.username, f.category) for f in confirmed
    )
    values = {_node_id(f): _linking_values(f) for f in confirmed}

    edges: list[IdentityEdge] = []
    union = _UnionFind([n.id for n in nodes])
    for i, left in enumerate(nodes):
        for right in nodes[i + 1 :]:
            shared = _shared_keys(values[left.id], values[right.id])
            if shared:
                edges.append(IdentityEdge(left.id, right.id, shared))
                union.union(left.id, right.id)

    clusters = tuple(sorted(union.clusters()))
    return IdentityGraph(nodes=nodes, edges=tuple(edges), clusters=clusters)


# --- Timeline ---------------------------------------------------------


def _parse_date(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        return as_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def build_timeline(findings: Sequence[Finding], *, now: datetime | None = None) -> Timeline:
    reference = as_utc(now or utcnow())
    dated: list[tuple[datetime, Finding]] = []
    for finding in findings:
        parsed = _parse_date(finding.details.get("creation_date"))
        if parsed is not None:
            dated.append((parsed, finding))
    if not dated:
        return Timeline()

    dated.sort(key=lambda pair: pair[0])
    entries = tuple(
        TimelineEntry(
            platform=finding.platform,
            username=finding.username,
            created_at=created.isoformat(),
            age_years=round((reference - created).days / _DAYS_PER_YEAR, 1),
        )
        for created, finding in dated
    )
    oldest_date, oldest = dated[0]
    newest_date, newest = dated[-1]
    dormant = tuple(
        entry.platform for entry in entries if entry.age_years >= _DORMANT_YEARS
    )
    return Timeline(
        entries=entries,
        oldest_platform=oldest.platform,
        oldest_date=oldest_date.isoformat(),
        newest_platform=newest.platform,
        newest_date=newest_date.isoformat(),
        span_years=round((newest_date - oldest_date).days / _DAYS_PER_YEAR, 1),
        dormant_old_accounts=dormant,
    )


# --- Contactos reconstruidos -----------------------------------------


def _email_matches_mask(email: str, mask: str) -> bool:
    """¿El correo aportado es compatible con una máscara tipo `j***@e***.com`?

    Las máscaras reales (holehe et al.) no conservan la longitud, así que se
    comparan solo los anclajes visibles: el prefijo antes del primer `*` y el
    sufijo tras el último `*` de cada parte (local y dominio).
    """
    if email.count("@") != 1 or "@" not in mask:
        return False
    email_local, email_domain = email.rsplit("@", 1)
    mask_local, mask_domain = mask.rsplit("@", 1)
    return _anchor_matches(email_local, mask_local) and _anchor_matches(email_domain, mask_domain)


def _anchor_matches(value: str, mask: str) -> bool:
    value, mask = value.casefold(), mask.casefold()
    if "*" not in mask:
        return value == mask
    prefix = mask.split("*", 1)[0]
    suffix = mask.rsplit("*", 1)[1]
    if len(value) < len(prefix) + len(suffix):
        return False
    return value.startswith(prefix) and value.endswith(suffix)


def reconstruct_contacts(
    findings: Sequence[Finding], provided_email: str | None
) -> tuple[ReconstructedContact, ...]:
    groups: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        for detail_key, kind in (("masked_email", "email"), ("masked_phone", "phone")):
            pattern = finding.details.get(detail_key)
            if isinstance(pattern, str) and pattern.strip():
                key = (kind, pattern.strip())
                groups.setdefault(key, set()).update(finding.sources)

    contacts: list[ReconstructedContact] = []
    for (kind, pattern), sources in sorted(groups.items()):
        consistent: bool | None = None
        if kind == "email" and provided_email:
            consistent = _email_matches_mask(provided_email, pattern)
        contacts.append(
            ReconstructedContact(
                kind=kind,
                pattern=pattern,
                sources=tuple(sorted(sources)),
                count=len(sources),
                consistent_with_provided=consistent,
            )
        )
    return tuple(contacts)


# --- Orquestación ----------------------------------------------------


def correlate(
    findings: Sequence[Finding],
    *,
    provided_email: str | None = None,
    now: datetime | None = None,
) -> CorrelationResult:
    return CorrelationResult(
        identity_graph=build_identity_graph(findings),
        timeline=build_timeline(findings, now=now),
        reconstructed_contacts=reconstruct_contacts(findings, provided_email),
    )
