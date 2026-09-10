#!/usr/bin/env bash
# Prepara las herramientas OSINT vendorizadas, cada una en su propio venv.
# Requiere red (PyPI y GitHub) y `uv`. Idempotente: reejecutar actualiza.
set -euo pipefail

# --- Versiones fijadas (cambiar aquí para actualizar) ---
MAIGRET_VERSION="0.6.5"
HOLEHE_VERSION="1.61"
# Blackbird no publica tags; se fija el commit de `main`.
BLACKBIRD_COMMIT="b45505080ef51bb3ef52dc29879ee6bef31e5b94"
BLACKBIRD_REPO="https://github.com/p1ngul1n0/blackbird.git"

VENDOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_VERSION="3.12"

echo "[osint] vendor dir: ${VENDOR_DIR}"
command -v uv >/dev/null || { echo "uv no está instalado" >&2; exit 1; }

# --- maigret (PyPI; trae su propia base de sitios) ---
echo "[osint] maigret ${MAIGRET_VERSION}"
uv venv --python "${PYTHON_VERSION}" "${VENDOR_DIR}/maigret/.venv"
uv pip install --python "${VENDOR_DIR}/maigret/.venv/bin/python" "maigret==${MAIGRET_VERSION}"

# --- holehe (PyPI) ---
echo "[osint] holehe ${HOLEHE_VERSION}"
uv venv --python "${PYTHON_VERSION}" "${VENDOR_DIR}/holehe/.venv"
uv pip install --python "${VENDOR_DIR}/holehe/.venv/bin/python" "holehe==${HOLEHE_VERSION}"

# --- blackbird (repo; no se publica en PyPI) ---
echo "[osint] blackbird ${BLACKBIRD_COMMIT:0:12}"
BB_DIR="${VENDOR_DIR}/blackbird"
if [ ! -d "${BB_DIR}/.git" ]; then
  git clone --filter=blob:none --no-checkout "${BLACKBIRD_REPO}" "${BB_DIR}"
fi
git -C "${BB_DIR}" fetch --filter=blob:none origin "${BLACKBIRD_COMMIT}"
git -C "${BB_DIR}" checkout -q "${BLACKBIRD_COMMIT}"
uv venv --python "${PYTHON_VERSION}" "${BB_DIR}/.venv"
uv pip install --python "${BB_DIR}/.venv/bin/python" -r "${BB_DIR}/requirements.txt"

# Descarga la lista de sitios (wmn-data.json) sin escanear ninguno; en tiempo de
# ejecución el adaptador pasa --no-update y usa esta copia local.
echo "[osint] blackbird: descargando lista de sitios"
( cd "${BB_DIR}" && ./.venv/bin/python blackbird.py \
    --username setup-warmup --json --filter "cat=__none__" >/dev/null 2>&1 || true )
rm -rf "${BB_DIR}/results"
test -f "${BB_DIR}/data/wmn-data.json" || {
  echo "[osint] aviso: no se descargó blackbird/data/wmn-data.json" >&2
}

echo "[osint] listo. Configura FEE_OSINT_ENGINE_MODE=real para usarlas."
