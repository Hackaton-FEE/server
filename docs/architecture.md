# Arquitectura del servidor

`Hackaton-FEE/server` contiene una API FastAPI sobre Python 3.12, con dependencias declaradas en `pyproject.toml` y resueltas en `uv.lock`. La aplicación se construye mediante una factory para aislar configuración, montaje de rutas y creación de instancias en pruebas.

La factory es `src/fee_server/main.py:create_app`. Las pruebas de comportamiento HTTP y configuración viven en `tests/test_api.py` y `tests/test_config.py`. El entorno usa uv 0.12.12; los comandos reproducibles están en [CONTRIBUTING.md](../CONTRIBUTING.md).

## Contrato actual

| Método y ruta | Respuesta |
| --- | --- |
| `GET /api/v1/health` | HTTP 200, `{"status":"ok","service":"fee-server","version":"0.2.0"}`. |
| `POST /api/v1/auth/passkey/registration/options` | HTTP 200, reto para crear una passkey. |
| `POST /api/v1/auth/passkey/registration/verify` | HTTP 201, sesión nueva (crea la cuenta). |
| `POST /api/v1/auth/passkey/authentication/options` | HTTP 200, reto para iniciar sesión. |
| `POST /api/v1/auth/passkey/authentication/verify` | HTTP 200, sesión nueva. |
| `POST /api/v1/auth/token/refresh` | HTTP 200, sesión rotada. |
| `POST /api/v1/auth/logout` | HTTP 204. |
| `GET /api/v1/auth/me` | HTTP 200, resumen de la cuenta (requiere `Authorization: Bearer`). |
| `GET /.well-known/assetlinks.json` · `GET /.well-known/apple-app-site-association` | HTTP 200, asociación de dominio para passkeys nativas. |
| `POST /api/v1/osint/scans` | HTTP 202, escaneo de huella digital encolado (requiere `Bearer`). |
| `GET /api/v1/osint/scans/{id}` | HTTP 200, estado y progreso del escaneo. |
| `GET /api/v1/osint/scans/{id}/results` | HTTP 200, proyección para el dashboard (Exposure Score y categorías). |
| `GET /api/v1/osint/scans/{id}/events` | HTTP 200, stream SSE de progreso. |
| `DELETE /api/v1/osint/scans/{id}` | HTTP 204, el usuario borra su escaneo. |
| `POST /api/v1/verification/email/request` · `.../confirm` | HTTP 200, verificación de correo (consentimiento para escanear a un tercero); sin estado, sin BD. |
| `POST /api/v1/assistant/chat` | HTTP 200, stream SSE del asistente de higiene de privacidad (LLM); sin persistencia. |

El contrato completo de autenticación, con ejemplos y notas para el cliente Flutter, está en [auth-contract.md](auth-contract.md).

El módulo OSINT descubre la huella digital de la propia identidad del usuario
orquestando varios motores open source. Su diseño, contrato detallado y decisiones
están en [osint-architecture.md](osint-architecture.md). En esta fase los motores
son simulaciones deterministas (`FEE_OSINT_ENGINE_MODE=fake`) que no realizan
peticiones de red; los adaptadores reales llegan en una fase posterior.

`GET /api/v1/health` confirma que la aplicación responde. No acredita disponibilidad de Google/Meta, estado de casos, captura de evidencia ni capacidad de retiro. Los endpoints interactivos de documentación se desactivan cuando `FEE_ENVIRONMENT` está configurado como `production`.

## Autenticación

El registro y el inicio de sesión usan **passkeys FIDO2/WebAuthn** nativas del sistema operativo: no hay nombre de usuario, correo ni contraseña. El servidor guarda solo un identificador aleatorio (`handle`) y una o varias llaves públicas por cuenta; los datos biométricos nunca salen del dispositivo. La sesión es un JWT de acceso corto más un refresh token opaco que se rota en cada uso.

La persistencia es SQLAlchemy sobre SQLite en local y PostgreSQL/Supabase en despliegue; el esquema lo gestiona Alembic (`migrations/`). Crear la app (`create_app`) prepara el engine pero no abre conexiones ni ejecuta trabajo externo.

El scaffold sigue sin colas, captura de evidencia ni envíos externos. El cliente `Hackaton-FEE/app` (Flutter) todavía no consume esta API.

## Asistente de higiene de privacidad (LLM)

`POST /api/v1/assistant/chat` (`domain/assistant/`) es un chat por streaming
(SSE) que guía al usuario en la remediación de su huella digital. Diseño:

- **Sin persistencia**: el cliente reenvía el historial de la conversación
  actual en cada petición; el servidor no lo guarda. Antepone su propio
  `system prompt` fijo (`domain/assistant/prompts.py`); el cliente nunca puede
  mandar un mensaje con rol `system`.
- **`fake`/`real`** (`FEE_ASSISTANT_MODE`, por defecto `fake` y forzado en
  `test`): igual patrón que los motores OSINT. En `real` usa un proveedor
  compatible con la API de OpenAI (`openai.AsyncOpenAI`) — NVIDIA por defecto
  (`FEE_ASSISTANT_BASE_URL`, `FEE_ASSISTANT_MODEL`, `FEE_ASSISTANT_API_KEY`).
- **Egreso a un tercero**: en modo real, el contenido de la conversación viaja
  por HTTPS al proveedor configurado. Sin datos de escaneos inyectados.
- **Límites de coste/abuso**: `@limiter.limit("15/minute")`, cotas
  configurables de nº de mensajes y caracteres por mensaje
  (`FEE_ASSISTANT_MAX_MESSAGES`, `FEE_ASSISTANT_MAX_MESSAGE_CHARS`) y de
  tokens de salida (`FEE_ASSISTANT_MAX_OUTPUT_TOKENS`).
- Un fallo del proveedor a mitad de la respuesta no puede cambiar el código
  HTTP (ya es `200`): se emite `event: error` y se cierra el stream.

## Límites de responsabilidad

La factory compone configuración y rutas sin ejecutar trabajo externo. Los routers declaran HTTP y los modelos expresan respuestas. Conserva lógica de negocio fuera del transporte cuando una nueva tarea realmente la requiera; no hay necesidad de crear capas vacías de antemano.

El servidor y sus pruebas no deben registrar URL de casos ni información personal. Cualquier contrato futuro debe distinguir preparado, enviado, recibido, retiro en origen y desindexación. Un hash no demuestra conocimiento cero ni transforma una captura en certificación.

## Roadmap, fuera de la entrega inicial

1. Acordar y probar desde Flutter la integración de salud de solo lectura.
2. Definir contrato de borradores y estados, persistencia y responsabilidad sobre datos antes de introducirlos.
3. Implementar un primer canal asistido con resultados verificables, en una tarea separada.
4. Evaluar KYC, imágenes íntimas, preservación de evidencia, terceros y escalamiento automático con sus propios requisitos.

La visión del documento conceptual no implica que esas integraciones existan ni que una petición garantice eliminación de contenido.
