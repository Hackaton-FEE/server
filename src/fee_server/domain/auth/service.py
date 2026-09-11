"""Autenticación por passkey y acceso temporal de pruebas.

Flujo sin usuario ni contraseña:
  1. registro:  options -> el SO crea una passkey -> verify -> se crea la cuenta
  2. login:     options -> el SO elige la passkey  -> verify -> nueva sesión

La cuenta se identifica por un `handle` aleatorio; el login localiza al usuario
por el `credential_id` que devuelve el autenticador (credencial descubrible).
El modo `testing` emite una sesión de una cuenta aleatoria nueva sin credencial.
"""

import secrets
import unicodedata

from sqlalchemy.orm import Session
from webauthn.helpers import base64url_to_bytes

from fee_server.core.config import Settings
from fee_server.core.problem import (
    InvalidChallengeError,
    InvalidCredentialError,
    InvalidSessionError,
    PasskeyDisabledError,
    TestingAccessDisabledError,
    UnknownCredentialError,
)
from fee_server.core.security import challenge as challenge_mod
from fee_server.core.security import tokens
from fee_server.db.models import User
from fee_server.domain.auth import repository, webauthn_gateway
from fee_server.domain.auth.schemas import (
    ChallengeOptionsResponse,
    MeResponse,
    SessionResponse,
    UserSummary,
)
from fee_server.util.time import as_utc, utcnow

HANDLE_BYTES = 16


def _clean_label(label: str) -> str:
    """Recorta a 64 y descarta caracteres de control."""
    printable = "".join(ch for ch in label if unicodedata.category(ch)[0] != "C")
    return printable.strip()[:64]


class AuthService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # ------------------------------------------------------------------ registro
    def start_registration(self, label: str) -> ChallengeOptionsResponse:
        self._require_passkey()
        handle = secrets.token_bytes(HANDLE_BYTES)
        clean_label = _clean_label(label)
        challenge, token = challenge_mod.issue_challenge(
            self._settings.jwt_secret,
            "register",
            self._settings.challenge_ttl_seconds,
            data={"handle": handle.hex(), "label": clean_label},
        )
        public_key = webauthn_gateway.registration_options(
            self._settings, user_handle=handle, label=clean_label, challenge=challenge
        )
        return ChallengeOptionsResponse(challenge_token=token, public_key=public_key)

    def finish_registration(self, challenge_token: str, credential: dict) -> SessionResponse:
        self._require_passkey()
        challenge, data = self._read_challenge(challenge_token, "register")

        raw_id = _credential_raw_id(credential)
        if repository.get_credential(self._session, raw_id) is not None:
            raise InvalidCredentialError()  # genérico: no confirmamos existencia

        verified = webauthn_gateway.verify_registration(
            self._settings, credential=credential, challenge=challenge
        )
        user = repository.create_user_with_credential(
            self._session,
            handle=bytes.fromhex(data["handle"]),
            label=data.get("label", ""),
            credential_id=verified.credential_id,
            public_key=verified.public_key,
            sign_count=verified.sign_count,
        )
        return self._issue_session(user)

    # --------------------------------------------------------------------- login
    def start_authentication(self) -> ChallengeOptionsResponse:
        self._require_passkey()
        challenge, token = challenge_mod.issue_challenge(
            self._settings.jwt_secret,
            "authenticate",
            self._settings.challenge_ttl_seconds,
        )
        public_key = webauthn_gateway.authentication_options(self._settings, challenge=challenge)
        return ChallengeOptionsResponse(challenge_token=token, public_key=public_key)

    def finish_authentication(self, challenge_token: str, credential: dict) -> SessionResponse:
        self._require_passkey()
        challenge, _ = self._read_challenge(challenge_token, "authenticate")

        stored = repository.get_credential(self._session, _credential_raw_id(credential))
        if stored is None:
            raise UnknownCredentialError()

        new_sign_count = webauthn_gateway.verify_authentication(
            self._settings,
            credential=credential,
            challenge=challenge,
            public_key=stored.public_key,
            sign_count=stored.sign_count,
        )
        # sign_count == 0 en ambos lados es normal (passkeys sincronizadas).
        # Un retroceso real con contador previo > 0 sugiere clonación.
        if stored.sign_count and new_sign_count <= stored.sign_count:
            raise InvalidCredentialError()

        stored.sign_count = new_sign_count
        stored.last_used_at = utcnow()
        stored.user.last_active_at = utcnow()
        return self._issue_session(stored.user)

    # ------------------------------------------------------------------- sesión
    def start_testing_session(self) -> SessionResponse:
        if self._settings.auth_mode != "testing":
            raise TestingAccessDisabledError()
        user = repository.create_testing_user(
            self._session, handle=secrets.token_bytes(HANDLE_BYTES)
        )
        return self._issue_session(user)

    def refresh(self, refresh_token: str) -> SessionResponse:
        row = repository.get_refresh_token(self._session, tokens.hash_refresh_token(refresh_token))
        if row is None:
            raise InvalidSessionError()
        if row.revoked_at is not None:
            # Reuso de un token ya rotado: posible robo -> se cierra todo.
            # Se confirma de inmediato porque después lanzamos un error (que en
            # otro caso haría rollback de esta revocación).
            repository.revoke_all_refresh_tokens(self._session, row.user_id)
            self._session.commit()
            raise InvalidSessionError()
        if as_utc(row.expires_at) < utcnow():
            raise InvalidSessionError()

        row.revoked_at = utcnow()
        user = repository.get_user(self._session, row.user_id)
        if user is None or (
            self._settings.auth_mode == "passkey"
            and repository.count_credentials(self._session, user.id) == 0
        ):
            raise InvalidSessionError()
        return self._issue_session(user)

    def logout(self, refresh_token: str) -> None:
        row = repository.get_refresh_token(self._session, tokens.hash_refresh_token(refresh_token))
        if row is not None and row.revoked_at is None:
            row.revoked_at = utcnow()

    def me(self, user: User) -> MeResponse:
        return MeResponse(
            id=user.id,
            label=user.label,
            created_at=as_utc(user.created_at),
            credentials_count=repository.count_credentials(self._session, user.id),
        )

    # ------------------------------------------------------------------ helpers
    def _require_passkey(self) -> None:
        if self._settings.auth_mode != "passkey":
            raise PasskeyDisabledError()

    def _read_challenge(self, token: str, purpose: str) -> tuple[bytes, dict]:
        try:
            return challenge_mod.read_challenge(self._settings.jwt_secret, token, purpose)
        except challenge_mod.InvalidChallenge as exc:
            raise InvalidChallengeError() from exc

    def _issue_session(self, user: User) -> SessionResponse:
        access = tokens.create_access_token(
            secret=self._settings.jwt_secret,
            subject=user.id,
            issuer=self._settings.jwt_issuer,
            audience=self._settings.jwt_audience,
            ttl_seconds=self._settings.access_token_ttl_seconds,
        )
        raw_refresh, token_hash = tokens.generate_refresh_token()
        repository.store_refresh_token(
            self._session,
            user_id=user.id,
            token_hash=token_hash,
            ttl_seconds=self._settings.refresh_token_ttl_seconds,
        )
        return SessionResponse(
            access_token=access,
            refresh_token=raw_refresh,
            expires_in=self._settings.access_token_ttl_seconds,
            user=UserSummary(id=user.id, label=user.label),
        )


def _credential_raw_id(credential: dict) -> bytes:
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str):
        raise InvalidCredentialError()
    try:
        return base64url_to_bytes(raw)
    except Exception as exc:  # noqa: BLE001 - entrada externa: cualquier fallo es 400
        raise InvalidCredentialError() from exc
