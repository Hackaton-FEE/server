# FEE Server

API FastAPI de FEE en Python 3.12. Incluye cuentas, autenticación por contraseña, sesiones persistentes y una base modular para los distintos tipos de escaneo. La [app Flutter](https://github.com/Hackaton-FEE/app) sigue usando su demo local; este cambio prepara el contrato del servidor.

## Arranque local

Requisitos: Python 3.12 y uv 0.12.12. Si necesitas instalar uv de forma aislada:

```bash
python3.12 -m venv .tooling
.tooling/bin/python -m pip install uv==0.12.12
export PATH="$PWD/.tooling/bin:$PATH"
```

```bash
uv sync --frozen
export FEE_AUTH_SECRET_KEY="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(48))')"
uv run --frozen alembic upgrade head
uv run --frozen uvicorn fee_server.main:create_app --factory --host 127.0.0.1 --port 8000 --reload --no-access-log --no-proxy-headers
```

SQLite usa `fee.db`, ignorado por Git. Las migraciones se ejecutan explícitamente; crear la app no conecta la base de datos ni modifica su esquema. Conserva la clave generada en tu gestor de secretos y reutilízala al reiniciar. Sin clave explícita, desarrollo genera una por factory: los access tokens dejan de validar después de reiniciar y los límites por IP no se comparten entre workers.

En desarrollo: [Swagger](http://127.0.0.1:8000/docs) y [OpenAPI](http://127.0.0.1:8000/openapi.json). `GET /api/v1/health` conserva su respuesta `{"status":"ok","service":"fee-server","version":"0.1.0"}` y solo comprueba que el proceso responde.

## Autenticación

| Método | Ruta | Resultado |
| --- | --- | --- |
| POST | `/api/v1/auth/register` | Crea una cuenta con correo y contraseña. |
| POST | `/api/v1/auth/login` | Emite access JWT y refresh token opaco. |
| POST | `/api/v1/auth/refresh` | Rota el refresh y emite un nuevo par. |
| GET | `/api/v1/auth/me` | Devuelve la cuenta autenticada. |
| GET | `/api/v1/auth/sessions` | Lista las sesiones activas propias. |
| DELETE | `/api/v1/auth/sessions/{session_id}` | Revoca una sesión propia. |
| POST | `/api/v1/auth/logout` | Revoca la sesión actual. |
| POST | `/api/v1/auth/change-password` | Cambia la contraseña y revoca todas las sesiones. |
| GET | `/api/v1/scans/capabilities` | Catálogo autenticado de proveedores y disponibilidad. |

La contraseña usa Argon2id. Los JWT contienen identificadores internos, emisor, audiencia y expiración; cada petición protegida verifica también el estado de la sesión en SQL. Los refresh se guardan únicamente como hash, caducan con la sesión y son de un solo uso. Reutilizar uno revoca la sesión completa, incluido el reemplazo. El cliente debe serializar las renovaciones y guardar el nuevo par de forma atómica.

Consulta [el contrato HTTP](docs/api-contract.md), [la arquitectura](docs/architecture.md) y [cómo añadir un proveedor](docs/scanning.md). No hay rutas de ejecución de escaneos todavía: Sherlock, Holehe, Maigret y HIBP aparecen como no disponibles hasta conectar sus adaptadores y su flujo de autorización. No se presentan resultados ficticios como escaneos reales.

## Configuración

[.env.example](.env.example) contiene todas las variables. Se leen variables de entorno; los archivos `.env` no se cargan automáticamente. `FEE_ENVIRONMENT` acepta `development`, `test` y `production`.

- Producción exige `FEE_DATABASE_URL` con `postgresql+psycopg://…` y `FEE_AUTH_SECRET_KEY` explícita, aleatoria y de al menos 32 bytes. Usa la misma clave en todos los workers.
- Access tokens: 15 minutos por defecto. Sesiones y refresh: 30 días de duración absoluta.
- Cinco intentos fallidos bloquean temporalmente el acceso a una cuenta durante cinco minutos. El error de login no distingue cuenta ausente, contraseña incorrecta, bloqueo o cuenta inactiva.
- Registro, login y refresh tienen además un límite SQL de 30 solicitudes por IP/ruta/minuto. Devuelve `429` y `Retry-After`; las IP se almacenan como HMAC temporal, sin texto original.
- Las solicitudes tienen un máximo de 16 KiB. Los errores de validación excluyen valores de entrada y los errores SQL no exponen consultas.
- CORS está cerrado por defecto. Para Flutter web configura `FEE_CORS_ORIGINS` como una lista JSON de orígenes exactos; en producción solo HTTPS. La app móvil nativa no necesita CORS.
- En producción se ocultan Swagger/OpenAPI. TLS y la confianza en cabeceras del proxy se configuran en la infraestructura. Los arranques incluidos deshabilitan proxy headers. Al desplegar, habilita cabeceras reenviadas solo desde proxies conocidos que eliminen los valores enviados por el cliente: el limitador usa la IP que Uvicorn entrega a la app.

Desactiva los logs de acceso como en los comandos anteriores. No registres cuerpos, contraseñas, tokens, correos ni objetivos de escaneo. Este backend aún no incluye verificación de correo, recuperación de contraseña por correo, MFA ni inicio de sesión social.

## Docker con PostgreSQL

```bash
export FEE_AUTH_SECRET_KEY="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker compose up --build
```

Compose arranca PostgreSQL, espera su healthcheck, ejecuta las migraciones y arranca la API en [localhost:8000](http://127.0.0.1:8000/docs). La API y las migraciones corren sin root, con filesystem de solo lectura. PostgreSQL conserva sus datos en un volumen y no publica un puerto al host. La contraseña fija de la base en Compose es exclusivamente de desarrollo; este archivo no es una configuración de producción.

```bash
docker compose down
```

`down` conserva el volumen. Las imágenes base usan tags de versión y no están fijadas por digest.

## Mantenimiento de sesiones

```bash
uv run --frozen python -m fee_server.maintenance cleanup-auth
```

Ejecuta esta operación como tarea de mantenimiento de tu infraestructura. Elimina sesiones cuya duración absoluta ya venció, sus tokens mediante cascada SQL y contadores de IP expirados. Conserva cuentas y todas las sesiones aún vigentes, incluso las revocadas, junto con su historial de refresh. Solo imprime cantidades agregadas. No se instala ningún scheduler automáticamente.

## Validación

```bash
uv lock --check
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen pytest
```

Las pruebas cubren contrato, configuración, credenciales, expiración y revocación de sesiones, refresh concurrente, aislamiento entre usuarios, límites HTTP y orquestación de proveedores mediante dobles locales. Las migraciones se validan separadamente del `create_all` de las fixtures. La CI usa dependencias congeladas en `uv.lock` y un servicio PostgreSQL 17 para ejecutar también migraciones y concurrencia contra SQL real.

Para ejecutar las tres pruebas PostgreSQL localmente, exporta `FEE_TEST_POSTGRES_URL` con una URL `postgresql+psycopg://…` hacia una base de pruebas. El usuario necesita crear esquemas. Las pruebas crean un esquema aleatorio y eliminan únicamente ese esquema al terminar; no migran esquemas existentes. Sin esa variable, las tres pruebas se omiten explícitamente.

## Estructura

```text
src/fee_server/
  main.py                 # Factory y composición de dependencias
  api/v1/                 # Montaje de rutas versionadas y salud
  core/                   # Configuración, SQL, límites y errores HTTP
  modules/
    auth/                 # Modelos SQL, esquemas, tokens, servicio y rutas
    scans/                # Contratos, registro, orquestación y catálogo
migrations/               # Historial Alembic
tests/                    # Contratos y comportamiento (incluye auth/ y scans/)
docs/                     # Arquitectura, API y extensión de escaneos
rules/                    # Reglas del equipo
skills/                   # Procedimientos de IA
```

Lee [AGENTS.md](AGENTS.md) y [CONTRIBUTING.md](CONTRIBUTING.md) antes de contribuir. Los cambios se revisan mediante PR; no se integra automáticamente a `main`.
