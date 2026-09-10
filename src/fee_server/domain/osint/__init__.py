"""Motor de descubrimiento de huella digital (OSINT).

Orquesta varios motores (Blackbird, Maigret, Holehe), normaliza sus salidas a un
esquema canónico, deduplica entre motores y calcula un Exposure Score para el
dashboard móvil. Ver `docs/osint-architecture.md`.
"""
