from fee_server.core.sse import format_event


def test_format_event_produces_valid_sse_lines():
    text = format_event("progress", {"a": 1})

    assert text == 'event: progress\ndata: {"a": 1}\n\n'
