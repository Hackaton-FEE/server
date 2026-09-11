# Contrato de acceso y autenticación

> Para el equipo Flutter (`Hackaton-FEE/app`). Todos los ejemplos usan datos
> ficticios. Errores en formato RFC 7807 (`application/problem+json`).

## Idea general

- `FEE_AUTH_MODE=passkey` es el valor predeterminado y conserva el flujo
  FIDO2/WebAuthn. Para distribuir la versión de pruebas sin autenticador,
  configurar explícitamente `FEE_AUTH_MODE=testing` en el servidor.
- **Sin usuario ni contraseña.** El registro y el login se hacen con la passkey
  nativa del sistema (Face ID / Touch ID / huella), respaldada por una llave
  privada que nunca sale del Secure Enclave / Android Keystore.
- Cada operación tiene **dos pasos**: `.../options` (el servidor devuelve un
  `challenge_token` opaco y el objeto `public_key` que se pasa al SO) y
  `.../verify` (se envía la respuesta del autenticador y el mismo
  `challenge_token`).
- El `challenge_token` es un token firmado y sin estado: guárdalo en memoria
  entre los dos pasos y devuélvelo **sin modificar**. Caduca en 120 s.
- El login es *usernameless*: `authentication/options` no lleva
  `allowCredentials`; el SO ofrece las passkeys disponibles para el dominio.

## Acceso temporal de pruebas (sin passkey ni registro previo)

Con `FEE_AUTH_MODE=testing`, el cliente abre directamente el formulario de
datos y obtiene una sesión en segundo plano; no pide alias de login, correo,
firma, certificado ni validación de dominio:

```http
POST /api/v1/auth/testing/session
Content-Type: application/json

{}
```

Respuesta `201 Created`, con el mismo `SessionResponse` usado por passkeys:

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaco>",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": { "id": "<UUID aleatorio>", "label": "Pruebas" }
}
```

El cuerpo vacío es obligatorio y estricto: campos como `id`, `user_id`,
`handle`, `label` o credenciales devuelven `422`. Cada creación asigna una
cuenta aleatoria nueva, sin `Credential`, y nunca selecciona una cuenta
existente. No hay una cuenta compartida entre testers. El endpoint tiene
límite de **10 solicitudes por minuto e IP**.

El cliente guarda estos tokens en almacenamiento seguro y los adjunta como
`Authorization: Bearer <access_token>` a los escaneos, estado, resultados,
eventos, verificación y chat. La API mantiene los controles de propietario,
consentimiento y cuotas existentes. El flujo de análisis funciona sin hacer
ninguna petición WebAuthn; omitir también el Bearer sigue devolviendo `401`.
Los datos del formulario determinan qué se analiza; `user.label` solo
identifica la sesión de pruebas.

`/auth/token/refresh`, `/auth/logout` y `/auth/me` funcionan igual en ambos
modos. El refresh se rota y conserva el `user.id`; en estas cuentas `/me`
devuelve `credentials_count: 0`. Reutilizar la sesión local evita crear otra
cuenta. Si se borra o pierde el refresh, una sesión nueva no recupera los
escaneos de la anterior ni los de las cuentas passkey.

En modo `testing`, las cuatro rutas `/auth/passkey/*` rechazan el acceso
con `403 passkey-disabled` antes de generar retos o verificar firmas. Las
credenciales almacenadas permanecen intactas. Volver a `FEE_AUTH_MODE=passkey`
restablece esas rutas y cierra la creación de sesiones de pruebas con
`403 testing-access-disabled`. Las cuentas sin credenciales dejan de poder
usar sus tokens de acceso y refresh (`401 invalid-session`). Las sesiones de cuentas con passkeys
siguen funcionando y las llaves no se borran.

Ambos archivos Compose propagan `FEE_AUTH_MODE` y usan `passkey` si se omite.
El despliegue debe habilitar `testing` antes de distribuir el cliente de
pruebas; el cliente debe manejar `testing-access-disabled` sin recurrir al
registro de passkeys. No se necesita migración ni borrar datos existentes.

## Paquete Flutter sugerido

`passkeys` (pub.dev) o el canal nativo equivalente. El objeto `public_key` que
devuelve el servidor ya viene en el formato JSON de WebAuthn; conviértelo a los
tipos que pida el plugin (los campos `challenge`, `user.id`, `rawId`, etc. son
base64url).

## Endpoints

### 1. Crear cuenta

```
POST /api/v1/auth/passkey/registration/options
{ "label": "Mi bóveda FEE" }        # opcional, máx. 64, se muestra en el gestor de passkeys

200 OK
{
  "challenge_token": "7b2263...e3.a1b2c3...",
  "public_key": { "rp": {...}, "user": {...}, "challenge": "...", "pubKeyCredParams": [...],
                  "authenticatorSelection": { "residentKey": "required", "userVerification": "required" } }
}
```

```
POST /api/v1/auth/passkey/registration/verify
{ "challenge_token": "<el de arriba>", "credential": <PublicKeyCredential JSON del SO> }

201 Created
{
  "access_token": "<JWT>", "refresh_token": "<opaco>",
  "token_type": "bearer", "expires_in": 3600,
  "user": { "id": "9a8f...", "label": "Mi bóveda FEE" }
}
```

### 2. Iniciar sesión

```
POST /api/v1/auth/passkey/authentication/options
{}

200 OK
{ "challenge_token": "...", "public_key": { "challenge": "...", "rpId": "fee.app", "userVerification": "required" } }
```

```
POST /api/v1/auth/passkey/authentication/verify
{ "challenge_token": "...", "credential": <PublicKeyCredential JSON del SO> }

200 OK   # mismo cuerpo que registration/verify
```

### 3. Mantener la sesión

```
POST /api/v1/auth/token/refresh
{ "refresh_token": "<opaco>" }

200 OK   # nuevo par de tokens; el refresh anterior queda revocado
```

El refresh se **rota en cada uso**. Si envías uno ya rotado, el servidor asume
robo y revoca todas las sesiones de esa cuenta (`401`).

```
POST /api/v1/auth/logout
{ "refresh_token": "<opaco>" }
204 No Content
```

### 4. Datos de la cuenta

```
GET /api/v1/auth/me
Authorization: Bearer <access_token>

200 OK
{ "id": "9a8f...", "label": "Mi bóveda FEE", "created_at": "2026-09-09T15:45:00Z", "credentials_count": 1 }
```

### 5. Verificación de correo (consentimiento para escanear a un tercero)

Prueba que el titular de un correo consiente que otra cuenta escanee su huella
digital. El `consent_token` resultante se pasa a `POST /api/v1/osint/scans`
(`target_type: "email"`). **Sin estado**: nada se guarda, el flujo viaja en
tokens firmados, igual que el `challenge_token`. Ambas rutas requieren
`Authorization: Bearer <access_token>` de la cuenta que pide el escaneo.

```
POST /api/v1/verification/email/request
{ "email": "titular@example.com" }

200 OK
{ "verification_token": "7b22...a1", "expires_in": 600 }
```

```
POST /api/v1/verification/email/confirm
{ "verification_token": "7b22...a1", "code": "1234" }

200 OK
{ "consent_token": "7b22...c3", "expires_in": 3600 }
```

> **Hackathon**: el código es estático (`"1234"`) y no se envía ningún correo.
> El contrato no cambiará al activar el envío real.

## Errores (RFC 7807)

| `type` (sufijo) | HTTP | Cuándo |
| --- | --- | --- |
| `invalid-challenge` | 400 | `challenge_token` manipulado, caducado o de otro propósito |
| `invalid-verification-token` | 400 | `verification_token` manipulado, caducado o con correo inválido |
| `invalid-verification-code` | 400 | el código no coincide |
| `invalid-consent` | 403 | `consent_token` inválido, caducado o de otro correo |
| `invalid-credential` | 400 | la respuesta del autenticador no verifica, o esa passkey ya está registrada |
| `unknown-credential` | 401 | la passkey no está registrada |
| `invalid-session` | 401 | JWT o refresh inválido / expirado / revocado |
| `testing-access-disabled` | 403 | Se solicita una sesión de pruebas sin `FEE_AUTH_MODE=testing` |
| `passkey-disabled` | 403 | Se intenta registro o login passkey en modo `testing` |
| `rate-limited` | 429 | demasiadas peticiones desde la misma IP |
| `payload-too-large` | 413 | cuerpo mayor a 16 KB |

## Almacenamiento en el cliente

- `access_token` y `refresh_token`: **solo** en `flutter_secure_storage`
  (Keychain / Keystore). Nunca en `SharedPreferences` ni en disco plano.
- El servidor usa `Authorization: Bearer`, no cookies: no hay CSRF, pero la
  custodia segura de los tokens es responsabilidad del cliente.

## Requisito de dominio (bloqueante para passkeys nativas)

El backend publica:

- `GET https://<rp_id>/.well-known/assetlinks.json` — Android
- `GET https://<rp_id>/.well-known/apple-app-site-association` — iOS (sin
  extensión, `Content-Type: application/json`, sin redirección)

El equipo Flutter debe aportar, por variables de entorno del backend:

| Variable | Valor |
| --- | --- |
| `FEE_WEBAUTHN_RP_ID` | dominio asociado (p. ej. `fee.app`) |
| `FEE_WEBAUTHN_ORIGINS` | `["https://fee.app", "android:apk-key-hash:<...>"]` (una entrada por build de Android) |
| `FEE_ANDROID_PACKAGE_NAME` | `io.fee.app` |
| `FEE_ANDROID_SHA256_FINGERPRINTS` | fingerprints SHA-256 del certificado de firma |
| `FEE_IOS_APP_IDS` | `["<TeamID>.<BundleID>"]` |

## Recuperación de cuenta

No hay recuperación por correo (por diseño). Se apoya en la sincronización de
passkeys (iCloud Keychain / Google Password Manager). Añadir varias passkeys a
una misma cuenta y los códigos de recuperación quedan en el roadmap.
