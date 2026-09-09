# Instrucciones para agentes

Este repositorio privado, `Hackaton-FEE/server`, contiene la API FastAPI en Python 3.12. Lee [la arquitectura](docs/architecture.md) antes de cambiar comportamiento y aplica estas reglas según la tarea:

- [Colaboración](rules/01-collaboration.md): ramas, alcance autorizado y revisión.
- [Producto y datos](rules/02-product-and-data.md): contrato inicial y tratamiento de información.
- [Calidad](rules/03-quality.md): validaciones y evidencia para el PR.

Las skills canónicas están en `skills/`. Abre explícitamente el archivo que corresponda cuando trabajes con IA:

- [fastapi-feature](skills/fastapi-feature/SKILL.md): rutas, modelos, configuración y comportamiento de la API.
- [api-contract](skills/api-contract/SKILL.md): propuesta o cambio del contrato HTTP compartido con `Hackaton-FEE/app`.

El servidor usa una app factory y conserva `GET /api/v1/health`. Los módulos `auth` y `scans` contienen autenticación con sesiones SQL y el catálogo/extensibilidad de proveedores. Lee [el contrato](docs/api-contract.md) y [los escaneos](docs/scanning.md). Las migraciones Alembic son explícitas; ningún proveedor externo está conectado. No implementa casos, KYC, procesamiento de imágenes íntimas ni envíos reales. La app Flutter sigue siendo una demo local sin conexión a este servidor.

El bootstrap inicial en `main` está autorizado; el trabajo posterior sigue [el flujo de PR](docs/workflow.md). Continúa las acciones cubiertas por la tarea y su autorización existente. Estas instrucciones no añaden una confirmación para cada edición, prueba o acción ya autorizada.
