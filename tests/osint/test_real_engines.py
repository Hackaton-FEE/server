"""Adaptadores reales: manejo de ausencia de herramienta y ruta de parseo.

La ejecución real de las herramientas se valida a mano con
`FEE_OSINT_ENGINE_MODE=real` y se documenta en el PR; aquí se sustituye
`run_tool` por un doble que deja el archivo de salida esperado.
"""

from pathlib import Path

import pytest

from fee_server.core.config import Settings
from fee_server.domain.osint.engines import real
from fee_server.domain.osint.engines.base import ENGINE_SKIPPED, EngineRequest
from fee_server.domain.osint.engines.process import ToolExecutionError, ToolRun
from fee_server.domain.osint.findings import CONFIRMED, RATE_LIMITED

FIXTURES = Path(__file__).parent / "fixtures"


def _real_settings(vendor_dir: str) -> Settings:
    return Settings(
        environment="development",
        jwt_secret="a-proper-production-secret-value-32chars",
        osint_engine_mode="real",
        osint_vendor_dir=vendor_dir,
    )


def _install_stub_tool(root: Path, tool: str, *executables: str) -> None:
    for executable in executables:
        path = root / tool / ".venv" / "bin" / executable
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
    if tool == "blackbird":
        (root / tool / "blackbird.py").write_text("# stub\n")


def test_missing_tool_raises_tool_execution_error(tmp_path):
    settings = _real_settings(str(tmp_path))  # vendor vacío

    with pytest.raises(ToolExecutionError):
        real.BlackbirdEngine(settings).run(EngineRequest(usernames=("alias",)))


def test_engines_skip_when_their_input_is_absent(tmp_path):
    settings = _real_settings(str(tmp_path))

    assert real.BlackbirdEngine(settings).run(EngineRequest(usernames=())).status == ENGINE_SKIPPED
    assert real.HoleheEngine(settings).run(EngineRequest(usernames=("x",))).status == ENGINE_SKIPPED
    ignorant_skip = real.IgnorantEngine(settings).run(EngineRequest(usernames=("x",)))
    assert ignorant_skip.status == ENGINE_SKIPPED


def test_blackbird_engine_parses_the_generated_report(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "blackbird", "python")
    settings = _real_settings(str(tmp_path))
    fixture = (FIXTURES / "blackbird_testuser12345.json").read_text("utf-8")

    def fake_run_tool(argv, *, cwd, **_kwargs):
        # Blackbird escribe el informe en `<cwd>/results/<user>_<fecha>_blackbird/`.
        report_dir = Path(cwd) / "results" / "testuser12345_09_10_2026_blackbird"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "testuser12345_09_10_2026_blackbird.json").write_text(fixture)
        return ToolRun(0, "", "", timed_out=False, truncated=False)

    monkeypatch.setattr(real, "run_tool", fake_run_tool)

    result = real.BlackbirdEngine(settings).run(EngineRequest(usernames=("testuser12345",)))

    assert result.findings
    assert any(f.platform == "GitLab" for f in result.findings)
    assert all(f.username == "testuser12345" for f in result.findings)
    # El adaptador limpia el informe tras leerlo.
    assert not (tmp_path / "blackbird" / "results").exists() or not list(
        (tmp_path / "blackbird" / "results").iterdir()
    )


def test_maigret_engine_parses_the_generated_report(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "maigret", "maigret")
    settings = _real_settings(str(tmp_path))
    fixture = (FIXTURES / "maigret_torvalds_simple.json").read_text("utf-8")

    def fake_run_tool(argv, *, cwd, **_kwargs):
        (Path(cwd) / "report_torvalds_simple.json").write_text(fixture)
        return ToolRun(0, "", "", timed_out=False, truncated=False)

    monkeypatch.setattr(real, "run_tool", fake_run_tool)

    result = real.MaigretEngine(settings).run(EngineRequest(usernames=("torvalds",)))

    github = next(f for f in result.findings if f.platform == "GitHub")
    assert github.status == CONFIRMED
    assert github.details["account_id"] == "1024025"


@pytest.mark.parametrize(
    "engine, tool, executables, engine_request, cli_proxy, expected_proxy",
    [
        (
            real.BlackbirdEngine,
            "blackbird",
            ("python",),
            EngineRequest(usernames=("alias",)),
            True,
            "http://norm-user:norm-pass@datacenter.example:8080",
        ),
        (
            real.MaigretEngine,
            "maigret",
            ("maigret",),
            EngineRequest(usernames=("alias",)),
            False,
            "http://norm-user:norm-pass@datacenter.example:8080",
        ),
        (
            real.HoleheEngine,
            "holehe",
            ("holehe",),
            EngineRequest(usernames=(), email="persona@example.com"),
            False,
            "http://res-user:res-pass@residential.example:7000",
        ),
        (
            real.IgnorantEngine,
            "ignorant",
            ("ignorant",),
            EngineRequest(usernames=(), phone="+34611223344"),
            False,
            "http://res-user:res-pass@residential.example:7000",
        ),
    ],
)
def test_engines_use_the_supported_proxy_transport(
    tmp_path, monkeypatch, engine, tool, executables, engine_request, cli_proxy, expected_proxy
):
    _install_stub_tool(tmp_path, tool, *executables)
    res_proxy = "http://res-user:res-pass@residential.example:7000"
    norm_proxy = "http://norm-user:norm-pass@datacenter.example:8080"
    settings = Settings(
        osint_vendor_dir=str(tmp_path),
        osint_residential_proxy_url=res_proxy,
        osint_normal_proxy_url=norm_proxy,
    )
    calls = []

    def fake_run_tool(argv, **kwargs):
        calls.append((argv, kwargs))
        return ToolRun(1, "", "", timed_out=False, truncated=False)

    monkeypatch.setattr(real, "run_tool", fake_run_tool)
    engine(settings).run(engine_request)

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert kwargs["proxy_url"] == expected_proxy
    assert ("--proxy" in argv) is cli_proxy
    # Maigret no debe combinar su ProxyConnector con el proxy de trust_env.
    if cli_proxy:
        assert argv[argv.index("--proxy") + 1] == expected_proxy
    else:
        assert expected_proxy not in argv


def test_engines_default_direct_egress_for_usernames_with_legacy_proxy(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "blackbird", "python")
    _install_stub_tool(tmp_path, "maigret", "maigret")
    _install_stub_tool(tmp_path, "holehe", "holehe")
    _install_stub_tool(tmp_path, "ignorant", "ignorant")

    legacy_proxy = "http://legacy-user:legacy-pass@proxy.example:7000"
    settings = Settings(osint_vendor_dir=str(tmp_path), osint_proxy_url=legacy_proxy)
    calls = []

    def fake_run_tool(argv, **kwargs):
        calls.append((argv, kwargs))
        return ToolRun(1, "", "", timed_out=False, truncated=False)

    monkeypatch.setattr(real, "run_tool", fake_run_tool)

    # Blackbird y Maigret usan salida directa (proxy_url="")
    real.BlackbirdEngine(settings).run(EngineRequest(usernames=("alias",)))
    assert calls[-1][1]["proxy_url"] == ""
    assert "--proxy" not in calls[-1][0]

    real.MaigretEngine(settings).run(EngineRequest(usernames=("alias",)))
    assert calls[-1][1]["proxy_url"] == ""
    assert "--proxy" not in calls[-1][0]

    # Holehe e Ignorant usan el proxy residencial efectivo (fallback a osint_proxy_url)
    real.HoleheEngine(settings).run(EngineRequest(usernames=(), email="persona@example.com"))
    assert calls[-1][1]["proxy_url"] == legacy_proxy

    real.IgnorantEngine(settings).run(EngineRequest(usernames=(), phone="+34611223344"))
    assert calls[-1][1]["proxy_url"] == legacy_proxy


def test_holehe_engine_parses_the_generated_csv(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "holehe", "holehe")
    settings = _real_settings(str(tmp_path))
    fixture = (FIXTURES / "holehe_confirmed.csv").read_text("utf-8")

    def fake_run_tool(argv, *, cwd, **_kwargs):
        (Path(cwd) / "holehe_123_persona@example.com_results.csv").write_text(fixture)
        return ToolRun(0, "", "", timed_out=False, truncated=False)

    monkeypatch.setattr(real, "run_tool", fake_run_tool)

    result = real.HoleheEngine(settings).run(
        EngineRequest(usernames=(), email="persona@example.com")
    )

    platforms = {f.platform: f for f in result.findings}
    assert platforms["imgur"].status == CONFIRMED
    assert platforms["lastpass"].details["masked_email"] == "jo****@gmail.com"


def test_ignorant_engine_parses_stdout(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "ignorant", "ignorant")
    settings = _real_settings(str(tmp_path))

    def fake_run_tool(argv, **_kwargs):
        assert argv[1:3] == ["34", "611223344"]  # +34 611223344 dividido por split_phone
        return ToolRun(
            0, "[+] instagram.com\n[x] amazon.com\n", "", timed_out=False, truncated=False
        )

    monkeypatch.setattr(real, "run_tool", fake_run_tool)

    result = real.IgnorantEngine(settings).run(EngineRequest(usernames=(), phone="+34611223344"))

    platforms = {f.platform: f for f in result.findings}
    assert platforms["instagram"].status == CONFIRMED
    assert platforms["amazon"].status == RATE_LIMITED
    assert result.status == "degraded"


def test_ignorant_engine_reports_ok_when_no_account_is_linked(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "ignorant", "ignorant")
    settings = _real_settings(str(tmp_path))
    monkeypatch.setattr(
        real,
        "run_tool",
        lambda *a, **k: ToolRun(
            0, "3 websites checked in 0.1 seconds\n", "", timed_out=False, truncated=False
        ),
    )

    result = real.IgnorantEngine(settings).run(EngineRequest(usernames=(), phone="+34611223344"))

    assert result.status == "ok"
    assert result.findings == ()


def test_ignorant_engine_errors_when_the_tool_did_not_run(tmp_path, monkeypatch):
    _install_stub_tool(tmp_path, "ignorant", "ignorant")
    settings = _real_settings(str(tmp_path))
    monkeypatch.setattr(
        real, "run_tool", lambda *a, **k: ToolRun(1, "", "boom", timed_out=False, truncated=False)
    )

    result = real.IgnorantEngine(settings).run(EngineRequest(usernames=(), phone="+34611223344"))

    assert result.status == "error"
    assert result.error_category == "no-output"
