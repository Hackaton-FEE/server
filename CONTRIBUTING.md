# Contribuir al servidor

Trabajamos dos personas con revisión cruzada. `main` conserva una versión comprobable; `work/engineer-1` y `work/engineer-2` identifican las ramas de cada ingeniero. Los cambios posteriores al bootstrap se integran por pull request y squash.

Para una tarea nueva se prefieren ramas breves creadas desde `main`, por ejemplo `feature/engineer-2-case-contract`. Consulta [el flujo completo](docs/workflow.md) para reutilizar o reemplazar una rama después de un squash sin perder trabajo.

Un PR describe el problema, el comportamiento final, su alcance y las verificaciones realizadas. Si cambia la API, incluye petición/respuesta de ejemplo con datos ficticios y enlaza el PR del cliente cuando corresponda. Antes de fusionar, la otra persona debe aprobar y los checks aplicables deben pasar. Es una **convención de equipo, sin enforcement**: el plan GitHub Free de esta organización no ofrece protección de ramas para estos repositorios privados.

Usa Python 3.12 y el entorno reproducible definido por `pyproject.toml` y `uv.lock`. Ejecuta desde la raíz:

```sh
uv lock --check
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen pytest
```

`Server checks` es el check automático esperado. Las pruebas del scaffold deben ser locales y no depender de Google, Meta u otros servicios externos.

Al trabajar con IA, sigue [AGENTS.md](AGENTS.md) y proporciona objetivo, criterios de aceptación y restricciones. La persona autora revisa el diff y responde por lo que se integra, incluyendo código generado.
