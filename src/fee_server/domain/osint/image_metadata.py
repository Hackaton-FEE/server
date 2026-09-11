"""Extracción pura de metadatos EXIF: GPS, cámara y fecha de captura."""

import io
import logging
import math
from datetime import datetime

from PIL import ExifTags, Image, UnidentifiedImageError

logger = logging.getLogger("fee_server.osint")

_GPS_IFD = ExifTags.IFD.GPSInfo
# Make/Model son texto libre de un archivo no confiable: se acota su longitud.
_MAX_CAMERA_MODEL_LENGTH = 200


def _to_decimal(dms: tuple, ref: str) -> float | None:
    """Convierte grados/minutos/segundos EXIF (con signo por `ref`) a decimal."""
    try:
        degrees, minutes, seconds = (float(part) for part in dms)
    except (TypeError, ValueError, OverflowError, ZeroDivisionError):
        return None
    if not all(math.isfinite(v) for v in (degrees, minutes, seconds)):
        return None
    if degrees < 0 or not 0 <= minutes < 60 or not 0 <= seconds < 60:
        return None
    value = degrees + minutes / 60 + seconds / 3600
    return -value if ref in ("S", "W") else value


def _gps_location(gps: dict) -> str | None:
    if gps.get(1) not in ("N", "S") or gps.get(3) not in ("E", "W"):
        return None
    lat = _to_decimal(gps.get(2), str(gps.get(1, "")))
    lon = _to_decimal(gps.get(4), str(gps.get(3, "")))
    if lat is None or lon is None or abs(lat) > 90 or abs(lon) > 180:
        return None
    return f"{lat:.6f},{lon:.6f}"


def _camera_model(exif: Image.Exif) -> str | None:
    make = str(exif.get(271, "")).strip()  # Make
    model = str(exif.get(272, "")).strip()  # Model
    combined = " ".join(part for part in (make, model) if part)
    return combined[:_MAX_CAMERA_MODEL_LENGTH] or None


def _taken_at(exif: Image.Exif) -> str | None:
    raw = (
        exif.get_ifd(ExifTags.IFD.Exif).get(36867) or exif.get(36867) or exif.get(306)
    )  # DateTimeOriginal | DateTime
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
            return _extract_exif(exif)
    except (  # Un EXIF malformado no debe afectar al resto del hallazgo.
        UnidentifiedImageError,
        OSError,
        ValueError,
        TypeError,
        SyntaxError,
        OverflowError,
        ZeroDivisionError,
        KeyError,
        IndexError,
        Image.DecompressionBombError,
    ):
        logger.warning("image_metadata: invalid-image-metadata")
        return {}


def _extract_exif(exif: Image.Exif) -> dict[str, object]:
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
