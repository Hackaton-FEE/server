"""Limitador de peticiones por IP (slowapi).

Almacenamiento en memoria: suficiente para una sola instancia. En un despliegue
con varias réplicas hay que migrar a un backend Redis (deuda conocida).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])
