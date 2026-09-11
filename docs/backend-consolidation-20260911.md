# Consolidación del backend — 11 de septiembre de 2026

Integra `enhancement` (correlación, reducción de coincidencias débiles y una
segunda pasada acotada sobre alias descubiertos) con el `main` que ya contiene
passkeys nativas, proxy OSINT, verificación de consentimiento y asistente SSE.
Las ramas anteriores de passkeys y proxy ya están incorporadas por los PR #2
y #3; no se sustituyen por sus versiones antiguas.

## Contrato compatible para Flutter

Se conservan métodos, rutas y campos anteriores. Los datos adicionales son:

| Respuesta | Campo | Tipo y significado |
| --- | --- | --- |
| `GET /api/v1/osint/scans/{id}` y `/results` | `engines` | Objeto por nombre de motor: `status`, `findings`, `runs`, `started_at`, `finished_at`, `error_category`. Fechas y error son anulables. |
| Ambas | `error_category` | Categoría general del fallo o `null`; no contiene entrada personal. |
| `/results` | `scan_status` | Estado persistido del escaneo. |
| `/results` | `coverage` | `complete`, `partial`, `none` o `unknown`. Describe ejecución de los motores solicitados, nunca cobertura total de Internet. |

`partial` también es verdadero si algún motor falla, devuelve resultados
degradados o ninguno pudo ejecutar una consulta. Un nombre sin alias, correo
o teléfono no alimenta los motores actuales: su cobertura es `none`, no una
prueba de ausencia de exposición. Un error de una primera pasada no desaparece
cuando la segunda tiene éxito. Las filas antiguas con un `error_category`
general siguen siendo consultables, sin error HTTP 500.

Los hallazgos conservan plataforma, alias, URL, estado, confianza, fuentes y
`details`. Los detalles públicos incluyen nombre, ID de cuenta, ubicación,
empresa, avatar, fechas, seguidores, seguidos, repositorios, gists, intereses,
enlaces y contactos enmascarados cuando los motores los obtienen. Los alias
internos para pivoteo producen relaciones del grafo; no se publican como un
campo crudo. El frontend debe mostrar la evidencia disponible y distinguir
coincidencias posibles, cuentas encontradas y pertenencia confirmada por el
usuario. Una puntuación cero con cobertura incompleta no acredita seguridad.

## Despliegue y datos

La revisión Alembic sigue siendo `0003`. Los nuevos campos de diagnóstico usan
el JSON existente; no se eliminan columnas ni se modifican credenciales. La
publicación requiere respaldo y ensayo de `alembic upgrade head`,
`alembic check` y lectura de escaneos previos sobre PostgreSQL aislado antes de
recrear la API. Conservar configuración privada, ambas huellas Android y
orígenes WebAuthn, JWT, proxy y datos en Oracle; acceder mediante Peterpad.

El `main` integrado exige `FEE_RATE_LIMIT_ENABLED=1` y
`FEE_VERIFICATION_STATIC_CODE` vacío en producción. La verificación por código
de demostración queda cerrada hasta implementar entrega real. La autoauditoría
con consentimiento sigue disponible. `FEE_ASSISTANT_MODE=disabled` responde
503 antes de abrir el stream; habilitar `real` requiere configurar el proveedor.
No se devuelve consejo simulado en producción.

La validación local de la integración pasó 247 pruebas, con dos pruebas de
red real omitidas por diseño y cobertura de 96.46 %. Se verificaron lock,
lint, formato, múltiples certificados Android, lectura de fallos antiguos,
pivoteo, cobertura y disponibilidad explícita del asistente. La evidencia del
despliegue y su imagen exacta se registra aparte en Oracle.
