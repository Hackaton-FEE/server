"""Descarga acotada de `avatar_url`, solo en memoria.

En modo real aplica guard SSRF, tope de bytes, tope de reloj de pared y proxy.
El host se resuelve una sola vez y la petición va contra esa IP validada, con
`Host`/SNI del hostname original, para evitar DNS rebinding.
"""

import io
import ipaddress
import logging
import socket
import time
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx
from PIL import Image

from fee_server.core.config import Settings

logger = logging.getLogger("fee_server.osint")

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORT = {"http": 80, "https": 443}
_FAKE_GPS_IFD = 34853  # GPSInfo


class ImageFetcher(Protocol):
    def fetch(self, url: str) -> bytes | None: ...


def _is_disallowed_ip(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolve_pinned_ip(host: str, port: int) -> str | None:
    """IP a la que se conectará, o `None` si cualquiera de las resueltas es insegura."""
    try:
        results = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        logger.warning("image_fetch: dns-resolution-failed")
        return None
    ips = [info[4][0] for info in results]
    if not ips or any(_is_disallowed_ip(ip) for ip in ips):
        return None
    return ips[0]


def _pinned_target(url: str) -> tuple[str, str] | None:
    """`(url_con_la_ip_validada, hostname_original)`, o `None` si no es seguro."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname or parts.username is not None:
        return None
    port = port or _DEFAULT_PORT[parts.scheme]
    ip = _resolve_pinned_ip(parts.hostname, port)
    if ip is None:
        return None
    host_literal = f"[{ip}]" if ":" in ip else ip
    netloc = host_literal if parts.port is None else f"{host_literal}:{parts.port}"
    pinned_url = urlunsplit(parts._replace(netloc=netloc))
    return pinned_url, parts.hostname


class FakeImageFetcher:
    """Sin red: genera en memoria una imagen 1x1 determinista con EXIF fijo."""

    def fetch(self, url: str) -> bytes | None:
        if not url:
            return None
        image = Image.new("RGB", (1, 1), color="white")
        exif = image.getexif()
        exif[271] = "FakeCam"  # Make
        exif[272] = "FE-1"  # Model
        exif[36867] = "2024:01:15 10:30:00"  # DateTimeOriginal
        gps = {
            1: "N",
            2: (19.0, 26.0, 0.0),
            3: "W",
            4: (99.0, 8.0, 0.0),
        }
        exif[_FAKE_GPS_IFD] = gps
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", exif=exif)
        return buffer.getvalue()


class RealImageFetcher:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, url: str) -> bytes | None:
        target = _pinned_target(url)
        if target is None:
            return None
        pinned_url, original_host = target

        proxy = self._settings.effective_osint_normal_proxy or None
        timeout = self._settings.osint_image_fetch_timeout_seconds
        max_bytes = self._settings.osint_image_max_bytes
        # El timeout de httpx es por operación; este tope acota la descarga completa.
        deadline = time.monotonic() + timeout

        try:
            with httpx.Client(
                proxy=proxy, timeout=timeout, follow_redirects=False, trust_env=False
            ) as client:
                with client.stream(
                    "GET",
                    pinned_url,
                    headers={
                        "Host": urlsplit(url).netloc,
                        "Accept-Encoding": "identity",
                    },
                    extensions={"sni_hostname": original_host},
                ) as response:
                    if response.is_redirect or response.status_code != httpx.codes.OK:
                        return None
                    content_type = response.headers.get("content-type", "")
                    if not content_type.startswith("image/"):
                        return None
                    if response.headers.get("content-encoding", "identity") != "identity":
                        return None
                    chunks = bytearray()
                    for chunk in response.iter_raw():
                        chunks.extend(chunk)
                        if len(chunks) > max_bytes:
                            logger.warning("image_fetch: byte-limit-exceeded")
                            return None
                        if time.monotonic() > deadline:
                            logger.warning("image_fetch: time-limit-exceeded")
                            return None
                    return bytes(chunks)
        except httpx.HTTPError:
            logger.warning("image_fetch: download-failed")
            return None


def build_image_fetcher(settings: Settings) -> ImageFetcher | None:
    """`None` si el forense de imágenes está apagado o en modo fake/test."""
    if not settings.osint_image_metadata_enabled:
        return None
    if settings.environment == "test" or settings.osint_engine_mode == "fake":
        return FakeImageFetcher()
    if settings.environment == "production" and not settings.effective_osint_normal_proxy:
        logger.warning(
            "image_fetch: FEE_OSINT_IMAGE_METADATA_ENABLED activo en producción sin "
            "FEE_OSINT_NORMAL_PROXY_URL/FEE_OSINT_PROXY_URL — las descargas de avatar "
            "saldrán directo desde el propio servidor en vez de por el proxy aislado."
        )
    return RealImageFetcher(settings)
