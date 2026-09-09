"""Archivos de asociación de dominio para passkeys nativas.

iOS y Android solo ofrecen una passkey a la app si el dominio (`rp_id`) publica
estos archivos enlazando con los identificadores de la app. Los valores reales
los aporta el equipo Flutter mediante variables de entorno; si están vacíos se
devuelve la estructura sin entradas.

Se sirven en la raíz (no bajo `/api/v1`), sin extensión en el caso de Apple y
sin redirecciones.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from fee_server.api.dependencies import SettingsDep

router = APIRouter(tags=["well-known"])

_CACHE_HEADER = {"Cache-Control": "public, max-age=3600"}


@router.get("/.well-known/assetlinks.json")
def android_asset_links(settings: SettingsDep) -> JSONResponse:
    if not settings.android_package_name:
        return JSONResponse(content=[], headers=_CACHE_HEADER)
    body = [
        {
            "relation": ["delegate_permission/common.get_login_creds"],
            "target": {
                "namespace": "android_app",
                "package_name": settings.android_package_name,
                "sha256_cert_fingerprints": list(settings.android_sha256_fingerprints),
            },
        }
    ]
    return JSONResponse(content=body, headers=_CACHE_HEADER)


@router.get("/.well-known/apple-app-site-association")
def apple_app_site_association(settings: SettingsDep) -> JSONResponse:
    body = {"webcredentials": {"apps": list(settings.ios_app_ids)}}
    return JSONResponse(content=body, headers=_CACHE_HEADER)
