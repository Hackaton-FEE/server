from fastapi import HTTPException


def unauthorized(code: str = "invalid_credentials") -> HTTPException:
    messages = {
        "invalid_credentials": "Credenciales inválidas.",
        "invalid_access_token": "La autenticación no es válida o ha expirado.",
        "invalid_refresh_token": "La sesión no se puede renovar. Inicia sesión de nuevo.",
    }
    return HTTPException(
        status_code=401,
        detail={"code": code, "message": messages[code]},
        headers={"WWW-Authenticate": "Bearer"},
    )


def registration_conflict() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"code": "registration_conflict", "message": "No se pudo registrar la cuenta."},
    )


def session_not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "session_not_found", "message": "Sesión no encontrada."},
    )
