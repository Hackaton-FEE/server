# FEE Server

Base del servidor de la plataforma FEE, separada de la [app Flutter](https://github.com/Hackaton-FEE/app). El [concepto del producto](https://github.com/Hackaton-FEE/documentation/blob/main/concepto-central-plataforma.md) vive en el repositorio de documentación.

Esta versión arranca una API FastAPI con una comprobación de vida. No guarda casos, URLs, imágenes ni datos personales; no envía solicitudes a plataformas externas. PostgreSQL, Redis, autenticación, autorización e integraciones de retiro siguen pendientes.

## Arranque local

Requisitos: Python 3.12 y uv 0.12.12. Desde la raíz del repositorio, si aún no tienes uv, puedes instalarlo en un entorno aislado:

```bash
python3.12 -m venv .tooling
.tooling/bin/python -m pip install uv==0.12.12
export PATH="$PWD/.tooling/bin:$PATH"
```

Instala las dependencias y arranca el servidor:

```bash
uv sync --frozen
uv run --frozen uvicorn fee_server.main:create_app --factory --host 127.0.0.1 --port 8000 --reload --no-access-log
```

En otra terminal:

```bash
curl --fail http://127.0.0.1:8000/api/v1/health
```

Respuesta HTTP 200:

```json
{"status":"ok","service":"fee-server","version":"0.1.0"}
```

Este endpoint verifica que el proceso responde; no indica la disponibilidad de una base de datos ni de servicios externos. En desarrollo hay documentación interactiva en [localhost:8000/docs](http://127.0.0.1:8000/docs) y el esquema en [localhost:8000/openapi.json](http://127.0.0.1:8000/openapi.json). Solo está implementada la ruta de salud; por ejemplo, `/api/v1/cases` responde 404.

## Configuración

`FEE_ENVIRONMENT` acepta `development` (valor por defecto), `test` y `production`. Un valor desconocido impide el arranque. En `production`, `/docs` y `/openapi.json` están deshabilitados. Cambiar esta variable no configura una infraestructura de producción.

```bash
export FEE_ENVIRONMENT=development
```

`.env.example` documenta las variables. Los archivos `.env` no se cargan automáticamente ni se versionan. No agregues credenciales al código, a las pruebas ni a las instrucciones para IA. Los comandos de arranque desactivan el registro de accesos de Uvicorn para evitar almacenar URLs y parámetros de consulta.

## Docker para desarrollo

Con Docker Engine y el plugin Compose disponibles:

```bash
docker compose up --build
```

El contenedor ejecuta Uvicorn con UID/GID 10001, sin privilegios de root. Compose publica el puerto únicamente en `127.0.0.1:8000` y monta `src/` en modo lectura para recargar los cambios. Dentro del contenedor Uvicorn escucha en `0.0.0.0` para recibir el tráfico del puerto publicado. No se incluyen bases de datos ni otros servicios.

```bash
docker compose down
```

La imagen es una base de desarrollo; la elección de hosting, TLS, autenticación, observabilidad y secretos se hará antes de un despliegue. `uv.lock` fija las dependencias Python; la imagen base `python:3.12-slim` recibe actualizaciones del sistema y no está fijada por digest.

## Validación

Los mismos comandos se ejecutan en GitHub Actions, en el job `Server checks`:

```bash
uv lock --check
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen pytest
```

Las pruebas verifican el contrato JSON de salud, el método HTTP permitido, la ausencia de rutas de casos, la documentación OpenAPI y el comportamiento de configuración. Los cambios de dependencias deben actualizar `pyproject.toml` y `uv.lock` juntos; ejecuta `uv lock` y vuelve a correr la validación. Los arranques y la CI usan `--frozen` para conservar las versiones del lock.

## Estructura

```text
src/fee_server/
  main.py                # Fábrica ASGI create_app
  core/config.py         # Configuración validada
  api/v1/router.py        # Registro de rutas versionadas
  api/v1/health.py        # Único endpoint inicial
tests/                   # Contrato HTTP y configuración
rules/                   # Reglas del equipo y de IA
skills/                  # Procedimientos de trabajo con IA
docs/                    # Arquitectura y decisiones
```

Lee [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md) y las carpetas `rules/` y `skills/` antes de implementar una funcionalidad. La arquitectura y el flujo de revisión describen cómo repartir el trabajo entre los dos ingenieros.

## Siguiente alcance

- Acordar el contrato de casos con la app y la documentación, antes de añadir persistencia.
- Diseñar autenticación, autorización por caso y minimización de datos antes de recibir información de personas.
- Elegir PostgreSQL, migraciones y política de retención cuando se implemente persistencia.
- Evaluar Redis y trabajos asíncronos cuando exista un proceso que los necesite.
- Validar cada integración externa y el consentimiento requerido antes de habilitar envíos.

Referencias de implementación: [pruebas con FastAPI](https://fastapi.tiangolo.com/tutorial/testing/) y [FastAPI en contenedores](https://fastapi.tiangolo.com/deployment/docker/).
