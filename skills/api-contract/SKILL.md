---
name: api-contract
description: Definir, revisar o cambiar contratos HTTP de Hackaton-FEE/server coordinados con el cliente Flutter. Usar para endpoints, payloads, errores o compatibilidad entre repositorios; no para refactors internos sin cambio observable.
---

# Contrato desde el servidor

Lee [arquitectura](../../docs/architecture.md) e inspecciona rutas, modelos y pruebas actuales. La app Flutter aún no está conectada. El contrato inicial es `GET /api/v1/health`, HTTP 200:

```json
{"status":"ok","service":"fee-server","version":"0.1.0"}
```

Para una modificación, describe método, ruta, obligatoriedad y tipos de campos, respuestas y errores que el consumidor necesita distinguir. Usa el OpenAPI generado y pruebas de respuesta como evidencia del comportamiento implementado; distingue cualquier propuesta todavía no implementada.

Conserva compatibilidad cuando sea posible. Si el consumidor debe cambiar, enlaza ambos PR y fija un orden de integración que mantenga cada `main` utilizable. No inventes endpoints de casos, identidad o reportes por analogía con el documento conceptual.

En flujos futuros, separa creación, envío, recepción, retiro en origen y desindexación; especifica la evidencia y el actor que cambian cada estado. No conviertas una respuesta HTTP de transporte en una garantía de resolución.

Valida el contrato con pruebas locales y datos ficticios, sin servicios externos. Actualiza documentación y ejemplos al cambiar el esquema y reporta si la prueba cubre solo el servidor o también un consumidor real. Sigue [el flujo de PR](../../docs/workflow.md).
