"""Ejecución de una herramienta externa como subproceso, acotada y sin shell.

Reglas: argumentos como lista (nunca cadena de shell), sin heredar el entorno
del servidor, con timeout que mata el proceso y tope de bytes de salida.
"""

import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
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

    if timeout <= 0 or max_output_bytes <= 0:
        raise ToolExecutionError("límites de ejecución no válidos")

    with tempfile.TemporaryDirectory(prefix="osint-home-") as home:
        env = _build_env(proxy_url, home, env_extra)
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv validado, sin shell
                list(argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                cwd=cwd,
                env=env,
            )
        except OSError as exc:
            raise ToolExecutionError("herramienta no disponible") from exc

        stdout = bytearray()
        stderr = bytearray()
        timed_out = truncated = False
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, (stdout, max_output_bytes))
                selector.register(proc.stderr, selectors.EVENT_READ, (stderr, _STDERR_CAP))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer, cap = key.data
                        available = cap - len(buffer)
                        if buffer is stdout and len(chunk) > available:
                            truncated = True
                        buffer.extend(chunk[:available])
                if not timed_out:
                    try:
                        proc.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        timed_out = True
        finally:
            # Matar el grupo también corta hijos que podrían seguir gastando
            # proxy después de que muera el proceso padre. Linux en producción.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()

    return ToolRun(
        -1 if timed_out else proc.returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
        timed_out=timed_out,
        truncated=truncated or timed_out,
    )
