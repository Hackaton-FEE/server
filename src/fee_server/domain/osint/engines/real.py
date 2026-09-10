"""Adaptadores reales: subproceso a las herramientas vendorizadas + parser.

Cada herramienta vive en `<FEE_OSINT_VENDOR_DIR>/<nombre>/` con su propio `.venv`
(lo prepara `vendor/osint/setup.sh`). El adaptador construye el `argv`, ejecuta
con `run_tool` y delega el parseo en `parsers`. Un ejecutable ausente lanza
`ToolExecutionError`, que el runner traduce en un motor `error` sin abortar el
escaneo.
"""

import contextlib
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

from fee_server.core.config import Settings
from fee_server.domain.osint.catalog import is_valid_identifier, split_phone
from fee_server.domain.osint.engines.base import (
    ENGINE_DEGRADED,
    ENGINE_ERROR,
    ENGINE_OK,
    ENGINE_SKIPPED,
    EngineRequest,
    EngineResult,
)
from fee_server.domain.osint.engines.parsers import (
    parse_blackbird_json,
    parse_holehe_csv,
    parse_ignorant_output,
    parse_maigret_simple_json,
)
from fee_server.domain.osint.engines.process import ToolExecutionError, run_tool
from fee_server.domain.osint.findings import RATE_LIMITED, Finding

# `osint_engine_timeout_seconds` es el presupuesto de reloj de pared por motor.
# El timeout por petición HTTP es un valor pequeño y fijo.
_PER_REQUEST_TIMEOUT = "15"
# Maigret parsea páginas completas (socid-extractor): necesita más margen.
_MAIGRET_BUDGET_FACTOR = 3
_BLACKBIRD_CONCURRENCY = "30"


def _newest(directory: str, pattern: str) -> Path | None:
    root = Path(directory)
    if not root.exists():
        return None
    matches = sorted(root.glob(f"**/{pattern}"), key=os.path.getmtime)
    return matches[-1] if matches else None


def _rmtree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


@contextlib.contextmanager
def _workdir() -> Iterator[str]:
    """Directorio temporal aislado para la salida de la herramienta."""
    with tempfile.TemporaryDirectory(prefix="osint-work-") as path:
        yield path


class _RealEngine:
    name = "real"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._vendor = Path(settings.osint_vendor_dir)

    @property
    def _timeout(self) -> int:
        return self._settings.osint_engine_timeout_seconds

    @property
    def _max_bytes(self) -> int:
        return self._settings.osint_max_output_bytes

    @property
    def _proxy(self) -> str:
        return self._settings.osint_proxy_url.get_secret_value()

    def _require(self, path: Path) -> Path:
        if not path.exists():
            raise ToolExecutionError(f"herramienta OSINT no encontrada: {self.name}")
        # Absoluta (el subproceso corre con cwd en un tmpdir) pero SIN resolver
        # symlinks: el `python` de un venv uv es un enlace al intérprete base y
        # resolverlo rompe la detección del venv (pyvenv.cfg).
        return path.absolute()

    @staticmethod
    def _safe_username(username: str) -> str:
        # Defensa en profundidad: el servicio ya validó, pero el adaptador no
        # debe pasar nada con forma de opción (`-x`) al subproceso.
        if not is_valid_identifier("username", username):
            raise ToolExecutionError("username no válido para OSINT")
        return username

    @staticmethod
    def _safe_email(email: str) -> str:
        if not is_valid_identifier("email", email):
            raise ToolExecutionError("email no válido para OSINT")
        return email

    @staticmethod
    def _safe_phone(phone: str) -> str:
        if not is_valid_identifier("phone", phone):
            raise ToolExecutionError("teléfono no válido para OSINT")
        return phone


class BlackbirdEngine(_RealEngine):
    name = "blackbird"

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.usernames:
            return EngineResult(self.name, ENGINE_SKIPPED)

        root = self._require(self._vendor / "blackbird").absolute()
        python = self._require(root / ".venv" / "bin" / "python")
        script = self._require(root / "blackbird.py")
        # Blackbird resuelve `data/` y `blackbird.log` contra el cwd y escribe el
        # informe en `<repo>/results/`; por eso se ejecuta con cwd en su propio
        # directorio. Con escaneos concurrentes del mismo alias el mismo día,
        # blackbird sobrescribe su informe (limitación conocida, aceptable con
        # `osint_max_concurrent_scans` bajo).
        results_dir = root / "results"
        _rmtree(results_dir)

        findings: list[Finding] = []
        degraded = False
        for raw_username in request.usernames:
            username = self._safe_username(raw_username)
            argv = [
                str(python),
                str(script),
                "--username",
                username,
                "--json",
                "--no-update",
                "--timeout",
                _PER_REQUEST_TIMEOUT,
                "--max-concurrent-requests",
                _BLACKBIRD_CONCURRENCY,
            ]
            if self._proxy:
                argv += ["--proxy", self._proxy]

            run_tool(
                argv,
                timeout=self._timeout,
                max_output_bytes=self._max_bytes,
                proxy_url=self._proxy,
                cwd=str(root),
            )
            report = _newest(str(results_dir), "*_blackbird.json")
            if report is None:
                degraded = True
                continue
            findings += parse_blackbird_json(report.read_text("utf-8"), username=username)
            _rmtree(report.parent)

        return EngineResult(self.name, ENGINE_DEGRADED if degraded else ENGINE_OK, tuple(findings))


class MaigretEngine(_RealEngine):
    name = "maigret"

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.usernames:
            return EngineResult(self.name, ENGINE_SKIPPED)

        binary = self._require(self._vendor / "maigret" / ".venv" / "bin" / "maigret")
        database = self._vendor / "maigret" / "data.json"

        findings: list[Finding] = []
        degraded = False
        for raw_username in request.usernames:
            username = self._safe_username(raw_username)
            with _workdir() as work:
                argv = [
                    str(binary),
                    username,
                    "-J",
                    "simple",
                    "--no-recursion",
                    "--no-autoupdate",
                    "--timeout",
                    _PER_REQUEST_TIMEOUT,
                    "-fo",
                    work,
                ]
                if database.exists():
                    argv += ["--db", str(database)]
                # Maigret 0.6.5 combina ProxyConnector(--proxy) con
                # ClientSession(trust_env=True): usar ambos conecta el proxy
                # contra sí mismo. El entorno cubre también sus activadores y
                # curl_cffi; no pasar --proxy evita ese doble salto.

                run_tool(
                    argv,
                    timeout=self._timeout * _MAIGRET_BUDGET_FACTOR,
                    max_output_bytes=self._max_bytes,
                    proxy_url=self._proxy,
                    cwd=work,
                )
                report = _newest(work, "report_*_simple.json")
                if report is None:
                    degraded = True
                    continue
                findings += parse_maigret_simple_json(report.read_text("utf-8"), username=username)

        return EngineResult(self.name, ENGINE_DEGRADED if degraded else ENGINE_OK, tuple(findings))


class HoleheEngine(_RealEngine):
    name = "holehe"

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.email:
            return EngineResult(self.name, ENGINE_SKIPPED)

        binary = self._require(self._vendor / "holehe" / ".venv" / "bin" / "holehe")
        email = self._safe_email(request.email)

        with _workdir() as work:
            argv = [
                str(binary),
                email,
                "--no-color",
                "--no-clear",
                "-C",
                "-T",
                _PER_REQUEST_TIMEOUT,
            ]
            run_tool(
                argv,
                timeout=self._timeout,
                max_output_bytes=self._max_bytes,
                proxy_url=self._proxy,
                cwd=work,
            )
            report = _newest(work, "holehe_*_results.csv")
            if report is None:
                return EngineResult(self.name, ENGINE_ERROR, (), "no-output")
            findings = tuple(parse_holehe_csv(report.read_text("utf-8")))

        # Sin proxy residencial, holehe topa rate-limit en casi todos los sitios.
        degraded = any(f.status == RATE_LIMITED for f in findings)
        return EngineResult(self.name, ENGINE_DEGRADED if degraded else ENGINE_OK, findings)


class IgnorantEngine(_RealEngine):
    """Vector de número telefónico (Amazon, Instagram, Snapchat).

    Ignorant solo imprime a stdout (no genera fichero), así que el adaptador
    parsea el resultado de `run_tool`. Comparte con Holehe la técnica de
    account-recovery y, por tanto, la sensibilidad a rate-limit desde cloud.
    """

    name = "ignorant"

    def run(self, request: EngineRequest) -> EngineResult:
        if not request.phone:
            return EngineResult(self.name, ENGINE_SKIPPED)

        binary = self._require(self._vendor / "ignorant" / ".venv" / "bin" / "ignorant")
        phone = self._safe_phone(request.phone)
        try:
            country, national = split_phone(phone)
        except ValueError as exc:
            return EngineResult(self.name, ENGINE_ERROR, (), f"invalid-phone: {exc}")

        with _workdir() as work:
            argv = [
                str(binary),
                country,
                national,
                "--no-color",
                "--no-clear",
                "-T",
                _PER_REQUEST_TIMEOUT,
            ]
            outcome = run_tool(
                argv,
                timeout=self._timeout,
                max_output_bytes=self._max_bytes,
                proxy_url=self._proxy,
                cwd=work,
            )

        if outcome.timed_out:
            return EngineResult(self.name, ENGINE_ERROR, (), "timeout")

        findings = tuple(parse_ignorant_output(outcome.stdout))
        # Ignorant cierra siempre con "N websites checked in ...". Sin esa marca
        # y sin hallazgos, la herramienta no llegó a ejecutarse.
        if not findings and "websites checked" not in outcome.stdout:
            return EngineResult(self.name, ENGINE_ERROR, (), "no-output")

        degraded = any(f.status == RATE_LIMITED for f in findings)
        return EngineResult(self.name, ENGINE_DEGRADED if degraded else ENGINE_OK, findings)
