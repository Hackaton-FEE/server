from uuid import UUID

from fastapi import APIRouter, Response, status

from fee_server.modules.auth.dependencies import AuthServiceDependency, CurrentActor
from fee_server.modules.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    SessionResponse,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, service: AuthServiceDependency) -> UserResponse:
    return service.register(str(body.email), body.password.get_secret_value())


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, service: AuthServiceDependency) -> TokenResponse:
    return service.login(str(body.email), body.password.get_secret_value())


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, service: AuthServiceDependency) -> TokenResponse:
    return service.refresh(body.refresh_token.get_secret_value())


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(actor: CurrentActor, service: AuthServiceDependency) -> Response:
    service.revoke_session(actor, actor.session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
def me(actor: CurrentActor, service: AuthServiceDependency) -> UserResponse:
    return service.me(actor)


@router.get("/sessions", response_model=list[SessionResponse])
def sessions(actor: CurrentActor, service: AuthServiceDependency) -> list[SessionResponse]:
    return service.sessions(actor)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: UUID, actor: CurrentActor, service: AuthServiceDependency
) -> Response:
    service.revoke_session(actor, session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: ChangePasswordRequest, actor: CurrentActor, service: AuthServiceDependency
) -> Response:
    service.change_password(
        actor, body.current_password.get_secret_value(), body.new_password.get_secret_value()
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
