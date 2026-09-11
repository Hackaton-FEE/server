"""`enrich_with_image_metadata`: orquesta fetch + extracción, tolerante a fallos."""

from fee_server.core.config import Settings
from fee_server.domain.osint.enrichment import enrich_with_image_metadata
from fee_server.domain.osint.findings import CONFIRMED, POTENTIAL_MATCH, Finding


def _finding(*, avatar_url=None, status=CONFIRMED, platform="Site") -> Finding:
    details = {"avatar_url": avatar_url} if avatar_url else {}
    return Finding(platform, "other", None, "alias", status, 80, ("blackbird",), details)


class _StubFetcher:
    def __init__(self, image_bytes: bytes | None = None, *, raises: bool = False):
        self.calls: list[str] = []
        self._image_bytes = image_bytes
        self._raises = raises

    def fetch(self, url: str) -> bytes | None:
        self.calls.append(url)
        if self._raises:
            raise RuntimeError("fetcher caído")
        return self._image_bytes


def _settings_with_fetcher(monkeypatch, fetcher) -> Settings:
    from fee_server.domain.osint import enrichment

    monkeypatch.setattr(enrichment, "build_image_fetcher", lambda _settings: fetcher)
    return Settings()


def _jpeg_with_camera() -> bytes:
    import io

    from PIL import Image

    image = Image.new("RGB", (1, 1))
    exif = image.getexif()
    exif[271] = "Acme"
    exif[272] = "Cam-1"
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif)
    return buffer.getvalue()


def test_a_confirmed_finding_with_an_avatar_gains_image_details(monkeypatch):
    fetcher = _StubFetcher(_jpeg_with_camera())
    settings = _settings_with_fetcher(monkeypatch, fetcher)
    findings = [_finding(avatar_url="https://cdn.example/a.png")]

    enriched = enrich_with_image_metadata(findings, settings)

    assert enriched[0].details["image_camera_model"] == "Acme Cam-1"
    assert enriched[0].details["avatar_url"] == "https://cdn.example/a.png"  # se conserva


def test_a_finding_without_avatar_url_is_left_untouched(monkeypatch):
    fetcher = _StubFetcher(_jpeg_with_camera())
    settings = _settings_with_fetcher(monkeypatch, fetcher)
    findings = [_finding()]

    enriched = enrich_with_image_metadata(findings, settings)

    assert enriched == findings
    assert fetcher.calls == []


def test_a_potential_match_finding_is_not_enriched(monkeypatch):
    fetcher = _StubFetcher(_jpeg_with_camera())
    settings = _settings_with_fetcher(monkeypatch, fetcher)
    findings = [_finding(avatar_url="https://cdn.example/a.png", status=POTENTIAL_MATCH)]

    enriched = enrich_with_image_metadata(findings, settings)

    assert enriched == findings
    assert fetcher.calls == []


def test_two_findings_sharing_an_avatar_only_fetch_once(monkeypatch):
    fetcher = _StubFetcher(_jpeg_with_camera())
    settings = _settings_with_fetcher(monkeypatch, fetcher)
    shared = "https://cdn.example/shared.png"
    findings = [
        _finding(avatar_url=shared, platform="SiteA"),
        _finding(avatar_url=shared, platform="SiteB"),
    ]

    enriched = enrich_with_image_metadata(findings, settings)

    assert fetcher.calls == [shared]
    assert all(f.details.get("image_camera_model") == "Acme Cam-1" for f in enriched)


def test_a_failing_fetcher_does_not_break_the_rest_of_the_scan(monkeypatch):
    fetcher = _StubFetcher(raises=True)
    settings = _settings_with_fetcher(monkeypatch, fetcher)
    findings = [
        _finding(avatar_url="https://cdn.example/broken.png", platform="Broken"),
        _finding(platform="Unaffected"),
    ]

    enriched = enrich_with_image_metadata(findings, settings)

    assert len(enriched) == 2
    assert "image_camera_model" not in enriched[0].details


def test_a_disabled_fetcher_leaves_findings_unchanged():
    findings = [_finding(avatar_url="https://cdn.example/a.png")]

    enriched = enrich_with_image_metadata(findings, Settings(osint_image_metadata_enabled=False))

    assert enriched == findings


def test_image_errors_do_not_log_personal_urls_or_exception_text(monkeypatch, caplog):
    class FailingFetcher:
        def fetch(self, url):
            raise RuntimeError(url)

    url = "https://cdn.example/private-person.jpg?token=private-token"
    settings = _settings_with_fetcher(monkeypatch, FailingFetcher())
    original = [_finding(avatar_url=url)]
    assert enrich_with_image_metadata(original, settings) == original
    assert "image-processing-failed" in caplog.text
    assert url not in caplog.text
    assert "private-token" not in caplog.text
