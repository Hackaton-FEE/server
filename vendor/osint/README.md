# Herramientas OSINT vendorizadas

El motor OSINT (`FEE_OSINT_ENGINE_MODE=real`) ejecuta tres herramientas open
source como subproceso, **cada una en su propio entorno virtual** para aislar sus
dependencias entre sí y del servidor (ADR-OSINT-02 en
[`docs/osint-architecture.md`](../../docs/osint-architecture.md)).

Este directorio versiona solo `setup.sh` y este README. Los entornos y el código
de las herramientas se generan con `setup.sh` y están ignorados por git
(`.gitignore`); son un paso de build/despliegue, no fuente del repositorio.

## Layout que espera el servidor

```
vendor/osint/
  blackbird/
    .venv/bin/python        # intérprete del venv de blackbird
    blackbird.py            # punto de entrada (repo clonado)
  maigret/
    .venv/bin/maigret       # consola instalada por pip
    data.json               # base de sitios (opcional; se pasa con --db)
  holehe/
    .venv/bin/holehe        # consola instalada por pip
```

Las rutas se derivan de `FEE_OSINT_VENDOR_DIR` (por defecto `vendor/osint`). Si
un ejecutable falta, ese motor se marca `error` y el escaneo continúa con los
demás.

## Preparación

```sh
./vendor/osint/setup.sh
```

Necesita red (PyPI y GitHub) y `uv`. Fija versiones en el propio script; para
actualizar una herramienta, cambia su versión ahí y vuelve a ejecutarlo.

## Validación manual del modo real

El modo `real` no entra en CI. Tras `setup.sh`:

Levanta el servidor con `FEE_OSINT_ENGINE_MODE=real` y lanza un escaneo de un
alias público (p. ej. `torvalds`) por la API. Comprueba que:

- `results.summary.engines_run` incluye `blackbird`, `maigret` y `holehe`;
- hay hallazgos `CONFIRMED` con `sources` de más de un motor;
- los logs no contienen el identificador, URLs de perfiles ni el contenido de
  `details` (solo `scan_id`, nombre de motor y contadores).
