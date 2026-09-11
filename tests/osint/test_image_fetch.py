"""`RealImageFetcher`: SSRF guard, streaming acotado, timeout, fake determinista."""

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from PIL import Image

from fee_server.core.config import Settings
from fee_server.domain.osint import image_fetch
from fee_server.domain.osint.image_fetch import (
    FakeImageFetcher,
    RealImageFetcher,
    _is_disallowed_ip,
    _pinned_target,
    build_image_fetcher,
)


class _Server(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ok.jpg":
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.end_headers()
            self.wfile.write(b"\xff\xd8\xff\xe0fake-jpeg-bytes")
        elif self.path == "/not-an-image":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/ok.jpg")
            self.end_headers()
        elif self.path == "/big.jpg":
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.end_headers()
            self.wfile.write(b"x" * 5000)
        elif self.path == "/slow.jpg":
            time.sleep(2)
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.end_headers()
            self.wfile.write(b"too-late")
        elif self.path == "/trickle.jpg":
            # Cada lectura cabe en el timeout de httpx; el total lo excede.
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.end_headers()
            for _ in range(4):
                self.wfile.write(b"x" * 10)
                self.wfile.flush()
                time.sleep(0.4)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server(monkeypatch):
    """Servidor loopback + bypass del guard SSRF (loopback siempre lo rechaza)."""
    monkeypatch.setattr(image_fetch, "_resolve_pinned_ip", lambda host, port: "127.0.0.1")
    with ThreadingHTTPServer(("127.0.0.1", 0), _Server) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            worker.join(timeout=3)


def _fetcher(base_url: str, **overrides) -> RealImageFetcher:
    settings = Settings(
        osint_image_max_bytes=1000, osint_image_fetch_timeout_seconds=1, **overrides
    )
    return RealImageFetcher(settings)


def test_accepts_a_small_image_with_the_right_content_type(local_server):
    result = _fetcher(local_server).fetch(f"{local_server}/ok.jpg")

    assert result == b"\xff\xd8\xff\xe0fake-jpeg-bytes"


def test_rejects_a_non_image_content_type(local_server):
    assert _fetcher(local_server).fetch(f"{local_server}/not-an-image") is None


def test_does_not_follow_redirects(local_server):
    assert _fetcher(local_server).fetch(f"{local_server}/redirect") is None


def test_cuts_off_a_download_that_exceeds_the_byte_cap(local_server):
    assert _fetcher(local_server).fetch(f"{local_server}/big.jpg") is None


def test_gives_up_after_the_timeout(local_server):
    assert _fetcher(local_server).fetch(f"{local_server}/slow.jpg") is None


def test_gives_up_on_a_download_that_trickles_past_the_wall_clock_budget(local_server):
    assert _fetcher(local_server).fetch(f"{local_server}/trickle.jpg") is None


def test_rejects_a_non_http_scheme():
    assert _pinned_target("ftp://example.com/a.jpg") is None


def test_rejects_a_url_without_hostname():
    assert _pinned_target("http:///a.jpg") is None


def test_rejects_a_hostname_that_resolves_to_loopback():
    assert _pinned_target("http://localhost/a.jpg") is None


def test_pins_the_connection_to_the_resolved_ip(monkeypatch):
    monkeypatch.setattr(image_fetch, "_resolve_pinned_ip", lambda host, port: "203.0.113.5")

    pinned_url, original_host = _pinned_target("https://avatars.example:8443/a.jpg")

    assert pinned_url == "https://203.0.113.5:8443/a.jpg"
    assert original_host == "avatars.example"


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "224.0.0.1", "0.0.0.0"],
)
def test_disallowed_ip_ranges_are_rejected(ip):
    assert _is_disallowed_ip(ip) is True


def test_a_public_ip_is_allowed():
    assert _is_disallowed_ip("93.184.216.34") is False


def test_fake_fetcher_is_deterministic_and_produces_a_valid_image():
    fetcher = FakeImageFetcher()

    first = fetcher.fetch("https://cdn.example/anything.png")
    second = fetcher.fetch("https://cdn.example/anything.png")

    assert first == second
    with Image.open(__import__("io").BytesIO(first)) as image:
        image.verify()


def test_fake_fetcher_returns_none_for_an_empty_url():
    assert FakeImageFetcher().fetch("") is None


def test_build_image_fetcher_returns_none_when_disabled():
    settings = Settings(osint_image_metadata_enabled=False)

    assert build_image_fetcher(settings) is None


def test_build_image_fetcher_uses_fake_under_test_environment():
    settings = Settings(environment="test", osint_engine_mode="real")

    assert isinstance(build_image_fetcher(settings), FakeImageFetcher)


def test_build_image_fetcher_uses_real_outside_test_environment_in_real_mode():
    settings = Settings(
        environment="development",
        jwt_secret="a-proper-production-secret-value-32chars",
        osint_engine_mode="real",
    )

    assert isinstance(build_image_fetcher(settings), RealImageFetcher)


def test_warns_when_production_has_no_proxy_configured(caplog):
    settings = Settings(
        environment="production",
        jwt_secret="a-proper-production-secret-value-32chars",
        osint_engine_mode="real",
        rate_limit_enabled=True,
        verification_static_code="",
    )

    with caplog.at_level("WARNING", logger="fee_server.osint"):
        build_image_fetcher(settings)

    assert any("sin FEE_OSINT_NORMAL_PROXY_URL" in message for message in caplog.messages)


@pytest.mark.parametrize(
    "url",
    [
        "http://cdn.example:invalid/a.jpg",
        "http://[broken/a.jpg",
        "http://user:secret@cdn.example/a.jpg",
    ],
)
def test_invalid_or_credential_bearing_urls_are_rejected(url):
    assert _pinned_target(url) is None


def test_shared_address_space_is_rejected():
    assert _is_disallowed_ip("100.64.0.1")


def test_environment_proxy_does_not_override_direct_download(local_server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    assert _fetcher(local_server).fetch(f"{local_server}/ok.jpg") is not None


def test_byte_limit_warning_does_not_expose_url(local_server, caplog):
    url = f"{local_server}/big.jpg"
    assert _fetcher(local_server).fetch(url) is None
    assert "byte-limit-exceeded" in caplog.text
    assert url not in caplog.text
