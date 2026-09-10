"""`run_tool`: subproceso acotado, sin shell, con entorno mínimo."""

import sys

import pytest

from fee_server.domain.osint.engines.process import ToolExecutionError, run_tool

_PY = sys.executable
_LIMITS = {"timeout": 10, "max_output_bytes": 10_000}


def test_captures_stdout_and_return_code():
    run = run_tool([_PY, "-c", "print('hola'); raise SystemExit(3)"], **_LIMITS)

    assert run.stdout.strip() == "hola"
    assert run.returncode == 3
    assert run.timed_out is False


def test_kills_the_process_on_timeout():
    run = run_tool([_PY, "-c", "import time; time.sleep(30)"], timeout=1, max_output_bytes=10_000)

    assert run.timed_out is True


def test_rejects_arguments_with_control_characters():
    with pytest.raises(ToolExecutionError):
        run_tool([_PY, "-c", "print(1)\n; rm -rf /"], **_LIMITS)


def test_rejects_empty_argv():
    with pytest.raises(ToolExecutionError):
        run_tool([], **_LIMITS)


def test_raises_when_the_executable_is_missing():
    with pytest.raises(ToolExecutionError):
        run_tool(["/nonexistent/osint-tool", "--help"], **_LIMITS)


def test_truncates_output_over_the_byte_cap():
    run = run_tool([_PY, "-c", "print('x' * 5000)"], timeout=10, max_output_bytes=1000)

    assert run.truncated is True
    assert len(run.stdout.encode("utf-8")) <= 1000


def test_injects_the_proxy_into_the_child_environment():
    run = run_tool(
        [_PY, "-c", "import os; print(os.environ.get('HTTPS_PROXY', 'none'))"],
        timeout=10,
        max_output_bytes=10_000,
        proxy_url="http://proxy.local:8080",
    )

    assert run.stdout.strip() == "http://proxy.local:8080"


def test_does_not_leak_the_server_environment(monkeypatch):
    monkeypatch.setenv("FEE_SECRET_MARKER", "should-not-appear")

    run = run_tool(
        [_PY, "-c", "import os; print(os.environ.get('FEE_SECRET_MARKER', 'absent'))"],
        timeout=10,
        max_output_bytes=10_000,
    )

    assert run.stdout.strip() == "absent"
