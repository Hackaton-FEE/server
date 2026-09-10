"""Asistente conversacional: guía de higiene de privacidad / remediación OSINT.

Sin persistencia: el cliente reenvía el historial de la conversación actual en
cada petición; el servidor antepone su propio *system prompt* y lo reenvía al
proveedor configurado. Ver `docs/osint-architecture.md`.
"""
