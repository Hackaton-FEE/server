# Arquitectura del servidor

`Hackaton-FEE/server` contiene una API FastAPI sobre Python 3.12, con dependencias declaradas en `pyproject.toml` y resueltas en `uv.lock`. La aplicación se construye mediante una factory para aislar configuración, montaje de rutas y creación de instancias en pruebas.

La factory es `src/fee_server/main.py:create_app`. Las pruebas de comportamiento HTTP y configuración viven en `tests/test_api.py` y `tests/test_config.py`. El entorno usa uv 0.12.12; los comandos reproducibles están en [CONTRIBUTING.md](../CONTRIBUTING.md).

## Contrato actual

| Método y ruta | Respuesta |
| --- | --- |
| `GET /api/v1/health` | HTTP 200, `{"status":"ok","service":"fee-server","version":"0.1.0"}`. |

El endpoint confirma que la aplicación responde. No acredita disponibilidad de Google/Meta, estado de casos, persistencia ni capacidad de retiro. Los endpoints interactivos de documentación se desactivan cuando `FEE_ENVIRONMENT` está configurado como `production`.

El scaffold no incorpora base de datos, autenticación de usuarios, colas, captura de evidencia ni envíos externos. El cliente del repositorio `Hackaton-FEE/app` conserva borradores en memoria y todavía no consume esta API.

## Límites de responsabilidad

La factory compone configuración y rutas sin ejecutar trabajo externo. Los routers declaran HTTP y los modelos expresan respuestas. Conserva lógica de negocio fuera del transporte cuando una nueva tarea realmente la requiera; no hay necesidad de crear capas vacías de antemano.

El servidor y sus pruebas no deben registrar URL de casos ni información personal. Cualquier contrato futuro debe distinguir preparado, enviado, recibido, retiro en origen y desindexación. Un hash no demuestra conocimiento cero ni transforma una captura en certificación.

## Roadmap, fuera de la entrega inicial

1. Acordar y probar desde Flutter la integración de salud de solo lectura.
2. Definir contrato de borradores y estados, persistencia y responsabilidad sobre datos antes de introducirlos.
3. Implementar un primer canal asistido con resultados verificables, en una tarea separada.
4. Evaluar KYC, imágenes íntimas, preservación de evidencia, terceros y escalamiento automático con sus propios requisitos.

La visión del documento conceptual no implica que esas integraciones existan ni que una petición garantice eliminación de contenido.
