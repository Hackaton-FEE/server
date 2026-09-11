"""Limitador de peticiones por IP (slowapi).

Almacenamiento en memoria: suficiente para una sola instancia. En un despliegue
con varias réplicas hay que migrar a un backend Redis (deuda conocida).
"""

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_enabled = os.getenv("FEE_RATE_LIMIT_ENABLED", "0").lower() in ("1", "true", "yes")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["120/minute"],
    enabled=_enabled,
)
