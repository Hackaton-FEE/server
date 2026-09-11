"""Extracción pura de EXIF: GPS, cámara, fecha de captura."""

import io

from PIL import Image

from fee_server.domain.osint.image_metadata import extract_image_metadata

_GPS_IFD = 34853


def _jpeg_bytes(*, exif=None) -> bytes:
    image = Image.new("RGB", (1, 1), color="white")
    buffer = io.BytesIO()
    if exif is not None:
        image.save(buffer, format="JPEG", exif=exif)
    else:
        image.save(buffer, format="JPEG")
    return buffer.getvalue()


def _exif_with_gps(*, lat_ref="N", lat=(19.0, 26.0, 0.0), lon_ref="W", lon=(99.0, 8.0, 0.0)):
    image = Image.new("RGB", (1, 1))
    exif = image.getexif()
    exif[271] = "Acme"
    exif[272] = "Cam-9000"
    exif[36867] = "2023:07:04 08:15:30"
    exif[_GPS_IFD] = {1: lat_ref, 2: lat, 3: lon_ref, 4: lon}
    return exif


def test_extracts_gps_camera_and_taken_at_from_full_exif():
    details = extract_image_metadata(_jpeg_bytes(exif=_exif_with_gps()))

    assert details["image_gps_location"] == "19.433333,-99.133333"
    assert details["image_camera_model"] == "Acme Cam-9000"
    assert details["image_taken_at"] == "2023-07-04T08:15:30"


def test_image_without_exif_returns_empty_details():
    assert extract_image_metadata(_jpeg_bytes()) == {}


def test_bytes_that_are_not_an_image_return_empty_details_without_raising():
    assert extract_image_metadata(b"this is definitely not an image") == {}


def test_partial_gps_data_is_omitted_rather_than_guessed():
    image = Image.new("RGB", (1, 1))
    exif = image.getexif()
    exif[_GPS_IFD] = {1: "N", 2: (19.0, 26.0, 0.0)}  # sin longitud

    details = extract_image_metadata(_jpeg_bytes(exif=exif))

    assert "image_gps_location" not in details
