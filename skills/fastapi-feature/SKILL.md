---
name: fastapi-feature
description: Implementar o revisar rutas, modelos, configuración y comportamiento del servidor Python 3.12 y FastAPI de Hackaton-FEE/server. Usar para cambios del backend; complementar con api-contract si cambia la interfaz consumida por Flutter.
---

# Cambios FastAPI

Lee [arquitectura](../../docs/architecture.md) y [producto y datos](../../rules/02-product-and-data.md). Define el resultado observable de la tarea antes de introducir módulos o dependencias.

Conserva la app factory y crea instancias independientes en pruebas. Mantén configuración, rutas y modelos según la estructura existente; no añadas base de datos, colas o servicios externos para ampliar el scaffold por iniciativa propia.

La API expone salud, autenticación con sesiones SQL y un catálogo de proveedores. Los features viven en `src/fee_server/modules/`; consulta el contrato vigente en `docs/api-contract.md`. Si una tarea añade comportamiento, especifica entrada, respuesta, errores y límites de responsabilidad. Ningún éxito HTTP de envío demuestra que un tercero eliminó contenido.

Mantén URL y datos personales fuera de logs, excepciones y ejemplos. La inicialización y las pruebas no deben enviar solicitudes reales a plataformas externas.

Ejecuta las comprobaciones de [calidad](../../rules/03-quality.md) y prueba comportamiento relevante: contrato HTTP, errores nuevos y configuración afectada. Si el cambio altera la interfaz pública, aplica también [api-contract](../api-contract/SKILL.md).

Entrega un diff acotado, resultados de pruebas y límites conocidos. Sigue [el flujo de PR](../../docs/workflow.md) dentro de la autorización de la tarea, sin añadir aprobaciones para ediciones ya autorizadas.
