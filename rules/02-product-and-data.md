# Producto y datos

- El contrato inicial es `GET /api/v1/health`, HTTP 200, con `status`, `service` y `version`. No existen rutas de casos, verificación de identidad o reportes en el scaffold.
- No registres URL de casos, query strings con datos personales, nombres, correos, documentos ni cuerpos de solicitudes. Si se añade observabilidad, usa identificadores internos y categorías de error, con datos ficticios en ejemplos y pruebas.
- Solicitud preparada, enviada, recibida, retiro en origen y desindexación son estados diferentes. Un nuevo contrato debe conservar esas diferencias y su evidencia.
- Un hash no implica conocimiento cero ni certificación. Documenta qué datos entran, se conservan y salen del servicio si una tarea incorpora ese procesamiento.
- KYC, imágenes íntimas, persistencia de evidencia, formularios externos, envíos y escalamiento automático pertenecen al roadmap. No los implementes como dependencias implícitas del scaffold o de una ruta de salud.
