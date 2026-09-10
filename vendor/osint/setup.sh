#!/usr/bin/env bash
# Prepara las herramientas OSINT vendorizadas, cada una en su propio venv.
# Requiere red (PyPI y GitHub) y `uv`. Idempotente: reejecutar actualiza.
set -euo pipefail

# --- Versiones fijadas (cambiar aquí para actualizar) ---
MAIGRET_VERSION="0.6.5"
HOLEHE_VERSION="1.61"
BLACKBIRD_REF="v1.0.0"

VENDOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_VERSION="3.12"

echo "[osint] vendor dir: ${VENDOR_DIR}"
command -v uv >/dev/null || { echo "uv no está instalado" >&2; exit 1; }

# --- maigret ---
echo "[osint] maigret ${MAIGRET_VERSION}"
uv venv --python "${PYTHON_VERSION}" "${VENDOR_DIR}/maigret/.venv"
uv pip install --python "${VENDOR_DIR}/maigret/.venv/bin/python" "maigret==${MAIGRET_VERSION}"

# --- holehe ---
echo "[osint] holehe ${HOLEHE_VERSION}"
uv venv --python "${PYTHON_VERSION}" "${VENDOR_DIR}/holehe/.venv"
uv pip install --python "${VENDOR_DIR}/holehe/.venv/bin/python" "holehe==${HOLEHE_VERSION}"

# --- blackbird (no se publica en PyPI: se clona el repo) ---
echo "[osint] blackbird ${BLACKBIRD_REF}"
if [ ! -d "${VENDOR_DIR}/blackbird/.git" ]; then
  git clone --depth 1 --branch "${BLACKBIRD_REF}" \
    https://github.com/p1ngul1n0/blackbird.git "${VENDOR_DIR}/blackbird"
else
  git -C "${VENDOR_DIR}/blackbird" fetch --depth 1 origin "${BLACKBIRD_REF}"
  git -C "${VENDOR_DIR}/blackbird" checkout -q "${BLACKBIRD_REF}"
fi
uv venv --python "${PYTHON_VERSION}" "${VENDOR_DIR}/blackbird/.venv"
uv pip install --python "${VENDOR_DIR}/blackbird/.venv/bin/python" \
  -r "${VENDOR_DIR}/blackbird/requirements.txt"

echo "[osint] listo. Configura FEE_OSINT_ENGINE_MODE=real para usarlas."
