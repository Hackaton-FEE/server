# Contrato HTTP v1

Este contrato está implementado en el servidor. La app Flutter continúa con repositorios de demo: no hay cambio coordinado del cliente en esta entrega. Todas las entradas son JSON; las rutas protegidas reciben `Authorization: Bearer <access_token>` y los secretos nunca se pasan en URLs.

## Salud

`GET /api/v1/health` es público y devuelve HTTP 200:

```json
{"status":"ok","service":"fee-server","version":"0.1.0"}
```

Comprueba el proceso, no la disponibilidad de SQL ni de proveedores externos. POST devuelve 405.

## Cuentas

`POST /api/v1/auth/register` recibe campos obligatorios `email` (correo válido, máximo 254 caracteres) y `password` (12–128 caracteres). El correo se recorta y convierte a minúsculas antes de comprobar unicidad. No se solicita nombre, teléfono ni documentos. Campos adicionales se rechazan.

```json
{"email":"persona@example.com","password":"contraseña ficticia larga"}
```

Devuelve 201 con `id` UUID, `email`, `is_active` booleano y `created_at` ISO8601 UTC. No inicia sesión ni envía correo. Un conflicto devuelve 409 con `detail.code=registration_conflict`; la respuesta no distingue qué restricción produjo el conflicto. Este estado sí permite inferir que un correo no se puede registrar, limitación del registro público sin verificación por correo.

`GET /api/v1/auth/me` requiere sesión y devuelve 200 con el mismo esquema público. No expone hashes ni contadores.

## Login y renovación

`POST /api/v1/auth/login` recibe `email` y `password` obligatorios. La contraseña de login acepta 1–128 caracteres para responder de forma uniforme a credenciales incorrectas. Devuelve 200:

```json
{
  "access_token":"<JWT firmado>",
  "refresh_token":"<token opaco>",
  "token_type":"bearer",
  "expires_in":900,
  "refresh_expires_in":2592000,
  "session_id":"5a253dd8-9af2-4976-875d-e216ff37db0a"
}
```

Las duraciones son segundos restantes y pueden variar por el tiempo transcurrido. El access caduca como máximo con la sesión. Los valores del ejemplo son ilustrativos; no son tokens utilizables.

`POST /api/v1/auth/refresh` recibe `refresh_token` obligatorio (40–256 caracteres) y devuelve un nuevo par con el mismo esquema. No requiere access token vigente. El refresh anterior queda consumido; reutilizarlo devuelve 401 y revoca la sesión completa. Renovar no amplía la duración absoluta de la sesión. Un refresh inválido, expirado o revocado devuelve `invalid_refresh_token`.

Desde Flutter:

1. Guardar el refresh usando almacenamiento seguro del dispositivo; mantener access en memoria cuando sea posible.
2. Serializar refresh con una sola operación compartida y sustituir ambos tokens de forma atómica.
3. Si la renovación falla, descartar las credenciales e iniciar sesión nuevamente. No reintentar automáticamente el refresh anterior después de una respuesta incierta: pudo haberse consumido.
4. Tras logout o cambio de contraseña, borrar credenciales locales.

Login incorrecto, cuenta ausente, bloqueada o inactiva devuelve la misma respuesta401 y `WWW-Authenticate: Bearer`:

```json
{"detail":{"code":"invalid_credentials","message":"Credenciales inválidas."}}
```

## Sesiones propias

`GET /api/v1/auth/sessions` requiere autenticación y devuelve 200 con una lista de sesiones activas propias. Cada entrada tiene `id`, `created_at`, `expires_at`, `last_used_at` (ISO8601 UTC) e `is_current` booleano. `last_used_at` registra login o última renovación, no cada petición al API. No se almacenan nombres de dispositivo ni user agents en esta entrega.

`DELETE /api/v1/auth/sessions/{session_id}` revoca una sesión propia por UUID y devuelve 204 sin cuerpo. Una sesión inexistente o ajena devuelve 404 `session_not_found`. Una sesión propia ya revocada puede revocarse nuevamente desde otra sesión activa (204).

`POST /api/v1/auth/logout` revoca la sesión que identifica el access token y devuelve 204. Su access y refresh dejan de funcionar inmediatamente en peticiones posteriores. Repetir con ese access devuelve 401 porque la autenticación ya fue revocada.

`POST /api/v1/auth/change-password` recibe `current_password` (1–128 caracteres) y `new_password` (12–128), requiere sesión activa y devuelve 204. Verifica la contraseña actual y actualiza el hash/revoca todas las sesiones en una transacción, incluida la actual. La siguiente acción es volver a iniciar sesión. Las credenciales incorrectas usan401 `invalid_credentials` y comparten el bloqueo de intentos de la cuenta.

## Catálogo de escaneo

`GET /api/v1/scans/capabilities` requiere autenticación. Devuelve 200 con `providers`, una lista de objetos `provider_id`, `name`, `capabilities` y `available`. Las capacidades son `username`, `email` o `breaches`.

Los adaptadores Sherlock, Holehe, Maigret y HIBP están declarados con `available=false`. La lista informa disponibilidad configurada, no prueba salud remota. No hay POST de escaneos, jobs ni resultados públicos todavía. Consulta [scanning.md](scanning.md) para extender el módulo.

## Errores comunes

| HTTP | Semántica |
| --- | --- |
| 401 | Bearer ausente/inválido/expirado o sesión/cuenta no autorizada. `invalid_access_token` en rutas protegidas. |
| 404 | Ruta ausente o sesión no accesible. `/api/v1/cases` sigue devolviendo404. |
| 405 | Método no permitido. |
| 409 | Conflicto de registro. |
| 413 | Cuerpo excede 16 KiB por defecto: `request_too_large`. |
| 422 | Validación: `detail` es una lista de `loc`, `type`, `msg`, sin `input` ni `ctx`. |
| 429 | Límite público auth: `rate_limited` y cabecera `Retry-After` en segundos. |
| 503 | Error de almacenamiento: `storage_unavailable`, sin detalles SQL. |

Los errores de negocio tienen `detail: {code, message}`. Los404/405 estándar conservan el formato FastAPI `detail: string`. Todas las respuestas HTTP incorporan `Cache-Control: no-store` y `X-Content-Type-Options: nosniff`. Swagger declara los cuerpos y el esquema HTTP Bearer; las tablas anteriores especifican los errores de negocio.

## Datos y límites pendientes

No se verifica propiedad del correo en el registro. Esta autenticación por sí sola no autoriza escanear correos ni identidades de terceros: ese flujo de consentimiento/verificación debe implementarse antes de habilitar proveedores. No se incluyen recuperación por correo, MFA, social login ni borrado público de cuentas. No hay pruebas end-to-end contra Flutter todavía.
