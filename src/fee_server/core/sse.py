"""Formato de eventos Server-Sent Events, compartido por los streams de la API."""

import json


def format_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
