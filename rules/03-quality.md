# Calidad del servidor

- Usa Python 3.12 y conserva `uv.lock` coherente con `pyproject.toml` cuando una tarea modifique dependencias.
- Mantén la app factory: crear una app no debe ejecutar envíos ni trabajo externo. Aísla configuración y routers de forma que las pruebas puedan crear instancias independientes.
- Valida formato, lint y pruebas con los comandos de [CONTRIBUTING.md](../CONTRIBUTING.md). Para cambios de API, prueba método/ruta, código HTTP y respuesta observable; añade casos de error cuando exista ese comportamiento.
- Las pruebas usan dobles para cualquier integración futura y no realizan reportes reales. Una prueba con mocks valida el contrato local, no la disponibilidad o aceptación de un tercero.
- Al cambiar `FEE_ENVIRONMENT`, preserva el comportamiento documentado de los endpoints de documentación en producción. No uses una configuración local como evidencia de despliegue.
- Declara pruebas ejecutadas y límites concretos. Una corrección editorial no requiere pruebas que solo repliquen el texto.
