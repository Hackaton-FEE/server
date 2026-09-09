from uuid import uuid4

from fee_server.modules.auth.dependencies import Actor, get_current_actor


def test_capabilities_require_authentication(client):
    assert client.get("/api/v1/scans/capabilities").status_code == 401


def test_authenticated_capabilities_catalog_is_explicit_about_unavailable_adapters(app, client):
    app.dependency_overrides[get_current_actor] = lambda: Actor(uuid4(), uuid4())
    response = client.get("/api/v1/scans/capabilities")
    assert response.status_code == 200
    assert response.json() == {
        "providers": [
            {
                "provider_id": "sherlock",
                "name": "Sherlock",
                "capabilities": ["username"],
                "available": False,
            },
            {
                "provider_id": "holehe",
                "name": "Holehe",
                "capabilities": ["email"],
                "available": False,
            },
            {
                "provider_id": "maigret",
                "name": "Maigret",
                "capabilities": ["username"],
                "available": False,
            },
            {
                "provider_id": "hibp",
                "name": "Have I Been Pwned",
                "capabilities": ["breaches"],
                "available": False,
            },
        ]
    }
    assert client.post("/api/v1/scans").status_code == 404
    assert client.post("/api/v1/scans/capabilities").status_code == 405
