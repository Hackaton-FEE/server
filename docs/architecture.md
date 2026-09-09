# Arquitectura del servidor

FEE usa un monolito modular FastAPI/Python 3.12. Cada feature conserva juntos sus contratos y reglas. Esto permite añadir proveedores de escaneo sin introducir nuevas responsabilidades en autenticación ni repartir prematuramente el proyecto en microservicios.

## Composición

`main.create_app(settings)` crea configuración, conexiones diferidas, servicio de tokens, limitador y registro de proveedores por instancia. No conecta a SQL, crea tablas ni llama a terceros durante la construcción. El lifespan libera el engine al cerrar. Alembic es el único mecanismo de evolución del esquema en ejecución normal.

`api/v1/router.py` registra explícitamente salud, auth y scans. `core/` contiene solo infraestructura compartida: configuración validada, sesiones SQL, errores HTTP sin datos de entrada, límite de cuerpo y limitador persistente de auth.

`modules/auth/` agrupa cuentas y sesiones del mismo producto. El router traduce HTTP; schemas valida entradas/salidas; security implementa primitivas con pwdlib y PyJWT; service ejecuta transacciones sobre modelos SQLAlchemy. No existe una capa repositorio adicional que repita llamadas SQL sin aportar un contrato. Si se añade otra persistencia, se extraerá una interfaz desde los casos de uso concretos.

`modules/scans/` tiene contratos de resultados, proveedores asíncronos, registro y orquestador independiente de HTTP. Su única ruta actual es un catálogo protegido. Lee [scanning.md](scanning.md) para registrar adaptadores y los requisitos previos a habilitar ejecución.

## Dependencias entre features

Scans importa únicamente `auth.dependencies.CurrentActor` para su límite HTTP. El orquestador y los proveedores no conocen contraseñas, JWT, tablas de usuarios ni FastAPI. Futuras rutas de jobs deben derivar el propietario del actor autenticado y consultar siempre por `(job_id, owner_id)`, nunca aceptar un propietario arbitrario desde el payload.

Los futuros workers reciben identificadores de trabajos autorizados y resultados normalizados. Las colas, almacenamiento de hallazgos y adaptadores externos se añadirán con un caso de uso implementado, política de retención y contrato comprobado. No hay carpetas vacías para servicios hipotéticos.

## Datos y seguridad implementada

- SQL conserva UUID, correo normalizado, hash Argon2id y estado/bloqueo de la cuenta.
- Cada sesión conserva propietario, creación, última renovación, expiración absoluta y revocación. Los refresh guardan SHA-256 y su consumo; el valor utilizable solo se entrega al cliente.
- JWT HS256 de corta duración exige `sub`, `sid`, `jti`, `iss`, `aud`, `iat`, `exp` y `type=access`. No contiene correo ni datos de escaneo. La autorización comprueba cuenta activa y sesión vigente en cada petición.
- El refresh usa una actualización condicional para que solo una petición pueda consumirlo. Consumo y reemplazo forman una transacción. Un replay persiste la revocación de toda la sesión antes de responder con error.
- Login y cambio de contraseña verifican mediante escritura condicional que la credencial no cambió durante el hash. El cambio de contraseña revoca todas las sesiones en la misma transacción.
- Los contadores por cuenta y por IP/ruta se actualizan en SQL; no dependen de memoria del worker. Las entradas de IP son HMAC y caducan al cerrar su ventana; se eliminan durante solicitudes posteriores.

Los correos de cuentas se conservan mientras exista la cuenta; esta entrega no incluye un flujo público de borrado. Los hashes de refresh consumidos deben conservarse hasta la expiración de su sesión para detectar replay. El comando `python -m fee_server.maintenance cleanup-auth` elimina sesiones vencidas y sus tokens en una transacción; su periodicidad corresponde al despliegue. No se persisten objetivos ni resultados de escaneo. No se transfieren datos a proveedores externos desde los endpoints actuales. Un hash no implica conocimiento cero ni certificación.

## Persistencia y entornos

SQLite simplifica desarrollo y pruebas locales. PostgreSQL con psycopg es obligatorio en configuración de producción y viene en Compose para probar la misma familia SQL. Las pruebas usan bases aisladas; ningún test depende de proveedores OSINT. Las migraciones pertenecen al repositorio y no se ejecutan automáticamente desde cada worker.

Una clave efímera por factory se permite solo en desarrollo/test. Para persistir access tokens entre reinicios y compartir límites entre workers configura una clave estable. Producción rechaza ausencia de clave y SQLite. TLS, secretos gestionados, backups y despliegue siguen siendo configuración de infraestructura.

## Origen de la adaptación

Se revisó [ICI-Laboratories/auth_services](https://github.com/ICI-Laboratories/auth_services) en commit `aabb6e30bddf59a5aba3d64a9ca4a37be1ea2d26`. La implementación para FEE adapta los patrones de `backend/app/core/security.py`, `backend/app/session_tokens.py`, `backend/app/domains/auth/` y `backend/app/domains/sessions/`: separación por features, Argon2id, refresh opaco, rotación, revocación y ownership.

La referencia no incluía un archivo de licencia en la revisión inspeccionada; se escribió una adaptación específica sin importar su código completo. No se trasladaron RBAC institucional, organizaciones, Google/Firebase, federación, auditorías con correos ni compatibilidad con JWT legacy sin claims obligatorios.

Como referencias de librerías se usaron [seguridad JWT de FastAPI](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/) y [SQLAlchemy para SQLite](https://docs.sqlalchemy.org/en/20/dialects/sqlite.html).

## Límites del producto

`GET /api/v1/health` conserva el contrato original y no acredita disponibilidad de SQL. La app Flutter aún no consume esta API. No existen rutas de casos, KYC, recepción de imágenes íntimas, preservación de evidencia, reportes externos ni solicitudes de retiro. Preparación, envío, recepción, retiro en origen y desindexación siguen siendo estados diferentes a definir cuando se implementen esos módulos.
