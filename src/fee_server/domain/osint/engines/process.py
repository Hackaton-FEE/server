"""Ejecución de una herramienta externa como subproceso, acotada y sin shell.

Reglas: argumentos como lista (nunca cadena de shell), sin heredar el entorno
del servidor, con timeout que mata el proceso y tope de bytes de salida.
"""

import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# Caracteres de control: un argumento que los contenga es sospechoso.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")
_STDERR_CAP = 4096


class ToolExecutionError(Exception):
    """La herramienta no pudo ejecutarse (ausente, argumentos inválidos…)."""


@dataclass(frozen=True, slots=True)
class ToolRun:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool


def _truncate(text: str | None, max_bytes: int) -> tuple[str, bool]:
    value = text or ""
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", "ignore"), True


def _build_env(proxy_url: str, home: str, extra: Mapping[str, str] | None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if proxy_url:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[key] = proxy_url
    if extra:
        env.update(extra)
    return env


def run_tool(
    argv: Sequence[str],
    *,
    timeout: float,
    max_output_bytes: int,
    proxy_url: str = "",
    cwd: str | None = None,
    env_extra: Mapping[str, str] | None = None,
) -> ToolRun:
    if not argv:
        raise ToolExecutionError("argv vacío")
    for part in argv:
        if not isinstance(part, str) or _UNSAFE.search(part):
            raise ToolExecutionError("argumento no válido")

    with tempfile.TemporaryDirectory(prefix="osint-home-") as home:
        env = _build_env(proxy_url, home, env_extra)
        try:
            proc = subprocess.run(  # noqa: S603 - argv es lista validada, sin shell
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, _ = _truncate(
                exc.stdout.decode("utf-8", "replace")
                if isinstance(exc.stdout, bytes)
                else exc.stdout,
                max_output_bytes,
            )
            return ToolRun(-1, stdout, "", timed_out=True, truncated=True)
        except FileNotFoundError as exc:
            raise ToolExecutionError("herramienta no encontrada") from exc

    stdout, truncated = _truncate(proc.stdout, max_output_bytes)
    return ToolRun(
        proc.returncode,
        stdout,
        (proc.stderr or "")[:_STDERR_CAP],
        timed_out=False,
        truncated=truncated,
    )
