"""Extracción de metadatos EXIF de una imagen ya descargada en memoria.

Función pura: no hace red ni escribe a disco, recibe bytes y devuelve
`details` listos para fusionarse en un `Finding` (ver `findings.py:DETAIL_KEYS`).
Deliberadamente solo extrae tres señales de alto valor de privacidad — GPS,
cámara, fecha de captura — no un volcado completo del EXIF (que puede traer
decenas de tags irrelevantes o incluso basura binaria).
"""

import io
import logging
from datetime import datetime

from PIL import ExifTags, Image, UnidentifiedImageError

logger = logging.getLogger("fee_server.osint")

_GPS_IFD = ExifTags.IFD.GPSInfo
# Make/Model son texto libre dentro del EXIF de un archivo de un tercero no
# confiable — acotar su longitud evita que un tag manipulado infle `details`.
_MAX_CAMERA_MODEL_LENGTH = 200


def _to_decimal(dms: tuple, ref: str) -> float | None:
    """Convierte grados/minutos/segundos EXIF (con signo por `ref`) a decimal."""
    try:
        degrees, minutes, seconds = (float(part) for part in dms)
    except (TypeError, ValueError):
        return None
    value = degrees + minutes / 60 + seconds / 3600
    return -value if ref in ("S", "W") else value


def _gps_location(gps: dict) -> str | None:
    lat = _to_decimal(gps.get(2), str(gps.get(1, "")))
    lon = _to_decimal(gps.get(4), str(gps.get(3, "")))
    if lat is None or lon is None:
        return None
    return f"{lat:.6f},{lon:.6f}"


def _camera_model(exif: Image.Exif) -> str | None:
    make = str(exif.get(271, "")).strip()  # Make
    model = str(exif.get(272, "")).strip()  # Model
    combined = " ".join(part for part in (make, model) if part)
    return combined[:_MAX_CAMERA_MODEL_LENGTH] or None


def _taken_at(exif: Image.Exif) -> str | None:
    raw = exif.get(36867) or exif.get(306)  # DateTimeOriginal | DateTime
    if not raw:
        return None
    try:
        parsed = datetime.strptime(str(raw).strip(), "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    return parsed.isoformat()


def extract_image_metadata(image_bytes: bytes) -> dict[str, object]:
    """EXIF -> `details` parciales. Nunca lanza: bytes corruptos -> `{}`."""
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image.verify()
        with Image.open(io.BytesIO(image_bytes)) as image:
            exif = image.getexif()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        # DecompressionBombError es un `Exception` plano en Pillow, no un
        # OSError/ValueError — sin listarlo aparte, una imagen con
        # dimensiones declaradas absurdas rompería la garantía de "nunca
        # lanza" de esta función.
        logger.warning("image_metadata: no se pudo abrir la imagen: %s", exc)
        return {}

    if not exif:
        return {}

    details: dict[str, object] = {}
    gps = exif.get_ifd(_GPS_IFD)
    if gps:
        location = _gps_location(gps)
        if location:
            details["image_gps_location"] = location

    camera = _camera_model(exif)
    if camera:
        details["image_camera_model"] = camera

    taken_at = _taken_at(exif)
    if taken_at:
        details["image_taken_at"] = taken_at

    return details
