# Contrato de autenticación por passkey

> Para el equipo Flutter (`Hackaton-FEE/app`). Todos los ejemplos usan datos
> ficticios. Errores en formato RFC 7807 (`application/problem+json`).

## Idea general

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
