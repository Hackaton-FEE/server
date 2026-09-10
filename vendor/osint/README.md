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

Necesita red (PyPI y GitHub) y `uv`; tarda ~1 min la primera vez. Fija versiones
en el propio script (Blackbird por commit de `main`, ya que no publica tags);
para actualizar una herramienta, cambia su versión ahí y vuelve a ejecutarlo. El
script además descarga `blackbird/data/wmn-data.json` (la lista de sitios), que
el adaptador usa en tiempo de ejecución con `--no-update`.

## Validación manual del modo real

El modo `real` no entra en CI. Tras `setup.sh`:

Tras `setup.sh`:

```sh
FEE_OSINT_INTEGRATION=1 uv run --frozen pytest tests/osint/test_integration_real.py --no-cov
```

ejecuta la cascada real contra `torvalds` y verifica que Blackbird y Maigret
corren, que hay >20 hallazgos y que la deduplicación cruza al menos uno entre
motores. Tarda ~1-2 min y hace peticiones de red reales.

Para una prueba de extremo a extremo por HTTP: levanta el servidor con
`FEE_OSINT_ENGINE_MODE=real` y lanza un escaneo. Comprueba que
`results.summary.engines_run` incluye los motores, que hay `CONFIRMED` con
`sources` de más de un motor, y que los logs no contienen el identificador,
URLs de perfiles ni el contenido de `details` (solo `scan_id`, motor y
contadores).
