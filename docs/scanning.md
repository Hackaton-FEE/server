# Escaneos de huella digital

El módulo `fee_server.modules.scans` establece una interfaz común para los features de búsqueda por alias, por correo y de brechas descritos en Osisn't. Ninguna integración externa está implementada o habilitada. El catálogo incluye Sherlock, Holehe, Maigret y Have I Been Pwned como proveedores planeados; no ejecuta sus herramientas ni consulta sus servicios.

## Contrato disponible

`GET /api/v1/scans/capabilities` requiere `Authorization: Bearer <access_token>` de una sesión vigente. Responde HTTP 200 con `providers`, una lista de objetos:

| Campo | Tipo | Significado |
| --- | --- | --- |
| `provider_id` | string | Identificador estable y único del adaptador. |
| `name` | string | Nombre del proveedor. |
| `capabilities` | array de strings | Operaciones: `username`, `email` o `breaches`. |
| `available` | boolean | Existe un adaptador registrado en esta instancia de la aplicación. |

Todos los proveedores iniciales tienen `available: false`. Un futuro `true` indicará registro de un adaptador, sin garantizar disponibilidad del tercero ni autorizar automáticamente búsquedas. Credenciales ausentes, inválidas o de una sesión revocada producen HTTP 401. La ruta sólo devuelve metadatos: no acepta identificadores personales, crea trabajos ni entrega hallazgos. `POST /api/v1/scans` permanece sin implementar y responde 404.

## Estructura y extensión

- `models.py`: entradas internas y hallazgos normalizados, estados por proveedor y catálogo HTTP.
- `providers.py`: protocolo `ScanProvider`, con `definition` y `async scan(target, capability)`.
- `registry.py`: IDs únicos, catálogo y registro explícito; `build_registry()` crea una instancia independiente.
- `orchestrator.py`: ejecución asíncrona acotada, normalización y aislamiento de fallos.
- `router.py`: transporte HTTP y dependencia pública `CurrentActor` de auth.

La factory almacena el registro en `app.state.scan_registry`. Los routers se montan bajo `/api/v1`. Auth no conoce los adaptadores de escaneo y éstos no necesitan conocer HTTP ni el almacenamiento de sesiones.

Para añadir un proveedor:

1. Crear su adaptador dentro de este módulo cuando exista una integración concreta, con un `ProviderDefinition` y el protocolo `ScanProvider`. Un adaptador recibe `ScanTarget` (`kind: username | email`, `value: SecretStr`) y una `Capability`. La operación `username` exige un alias; `email` y `breaches` exigen un correo. El adaptador debe validar el formato admitido por el tercero antes de consultarlo.
2. Traducir únicamente información necesaria a `Finding`: `kind` (`account` o `breach`), `service` (slug estable) y `url` HTTP(S) opcional, de hasta 2083 caracteres y sin credenciales embebidas. No devolver volcados del proveedor, credenciales, contraseñas expuestas ni metadatos arbitrarios. Un hallazgo es una coincidencia candidata y no demuestra que la persona sea propietaria de una cuenta.
3. Registrar la instancia explícitamente mediante `build_registry(providers=(adapter,))` en la composición de la aplicación o del futuro worker. Los IDs duplicados se rechazan; un adaptador de un proveedor ya planeado debe conservar sus capacidades declaradas. Si se añade una nueva operación, ampliar su contrato y las pruebas antes de publicarla.
4. Probar el mapeo, fallos y cancelación mediante dobles locales. La prueba de un adaptador simulado no verifica la disponibilidad ni la precisión de un tercero.

## Ejecución interna y límites

`ScanOrchestrator(registry).run(target, capability, provider_ids=None)` ejecuta los proveedores compatibles del catálogo; una selección explícita permite limitar el trabajo. Selecciones vacías, repetidas, desconocidas o incompatibles fallan antes de cualquier ejecución. Los resultados conservan el orden de selección y la procedencia por proveedor; se eliminan hallazgos idénticos dentro de cada proveedor, sin perder la atribución entre proveedores.

| Estado por proveedor | Interpretación |
| --- | --- |
| `completed` | El adaptador terminó y sus resultados cumplen el contrato; puede haber cero hallazgos. |
| `failed` | Falló el adaptador, devolvió resultados inválidos o excedió el límite de hallazgos. |
| `timed_out` | El proveedor excedió el tiempo permitido. |
| `unavailable` | Hay una entrada de catálogo, pero ningún adaptador registrado. |

No se convierte un fallo o una ejecución sin adaptadores en un escaneo exitoso ni en un índice de exposición cero. No se calcula un Exposure Score. Un resultado vacío de un proveedor que terminó tampoco prueba ausencia de exposición en Internet.

Los valores por defecto son 3 proveedores concurrentes, 20 segundos por proveedor activo y un máximo de 1000 hallazgos por proveedor antes de deduplicar. El semáforo se comparte entre llamadas de una misma instancia del orquestador. El tiempo en espera del semáforo no consume el timeout; estos límites no son globales entre procesos. Un proveedor que falla no cancela a los demás. La cancelación del llamador sí se propaga.

Los adaptadores deben usar I/O asíncrono cancelable y sus propios límites de respuesta, timeouts de red y controles de frecuencia. `asyncio` no puede detener código síncrono que bloquea el event loop ni una librería que ignora la cancelación. Herramientas de CLI o trabajo intensivo deben ejecutarse en un proceso de worker aislado con cancelación efectiva, nunca directamente dentro de un handler HTTP.

## Límite del futuro worker y autorización

El orquestador es una primitiva interna, sin autorización propia y sin ruta pública de ejecución. Antes de exponer envíos debe implementarse un caso de uso que valide la sesión del actor, la autorización sobre el identificador y el consentimiento aplicable. Autenticar una cuenta no demuestra posesión de un correo o alias arbitrario. Crear un trabajo debe asignarle el `user_id` desde el actor autenticado, nunca desde un campo controlado por el cliente; consultar o cancelar trabajos y leer resultados debe exigir ese mismo propietario.

Cuando se implemente el primer escaneo real, acordar conjuntamente almacenamiento, cola, idempotencia, vencimiento, reintentos, cuotas y cancelación; entonces se podrá pasar al worker un identificador interno del trabajo y resolver de forma controlada la entrada necesaria. No hay tablas, cola, trabajos persistentes, caché ni políticas de purga implementados para escaneos en esta entrega. Los requisitos de cifrado y retención del documento conceptual siguen pendientes de implementación.

El catálogo no recibe ni conserva datos personales. La primitiva interna mantiene el objetivo sólo en memoria; `SecretStr` oculta su representación y serialización accidental, pero no cifra la memoria. Un adaptador deberá revelar el valor únicamente al realizar la consulta autorizada, y documentar qué tercero lo recibe. Los resultados pueden contener URLs personales: sólo un futuro propietario autorizado debe poder leerlos. El módulo no registra objetivos, URLs, query strings ni respuestas; los fallos se convierten en categorías fijas sin copiar el texto de excepciones externas.
