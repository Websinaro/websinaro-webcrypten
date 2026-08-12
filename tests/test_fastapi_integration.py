import os
os.environ["MASTER_KEY"] = "Xk9pQ2vN8mL4wR7tY1zA6bC3dF5gH0jK+/=="

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import Response as PlainResponse

from websinaro.webcrypten import webcryptpen, WebCryptPen
from websinaro.webcrypten.middleware.fastapi_mw import WebsinaroMiddleware, ENCRYPT_HEADER


@pytest.fixture
def app():
    app = FastAPI()
    app.add_middleware(WebsinaroMiddleware, webcryptpen_instance=webcryptpen)

    @app.post("/echo")
    async def echo(request: Request):
        decrypted = await request.body()
        return PlainResponse(decrypted)

    @app.get("/plain")
    async def plain():
        return {"msg": "not encrypted"}

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_encrypted_round_trip(client):
    plaintext = b"hello from fastapi client"
    token = webcryptpen.encrypt(plaintext)

    resp = client.post("/echo", content=token, headers={ENCRYPT_HEADER: "true"})

    assert resp.status_code == 200
    assert resp.headers.get(ENCRYPT_HEADER) == "true"

    decrypted_response = webcryptpen.decrypt(resp.text)
    assert decrypted_response == plaintext


def test_unencrypted_request_passes_through(client):
    resp = client.get("/plain")
    assert resp.status_code == 200
    assert resp.json() == {"msg": "not encrypted"}
    assert ENCRYPT_HEADER not in resp.headers


def test_tampered_token_returns_400(client):
    token = webcryptpen.encrypt(b"hello")
    tampered = token[:10] + ("A" if token[10] != "A" else "B") + token[11:]

    resp = client.post("/echo", content=tampered, headers={ENCRYPT_HEADER: "true"})

    assert resp.status_code == 400


def test_wrong_key_cannot_decrypt(client):
    other_pen = WebCryptPen(master_key="ZzZ9xX8yY7wW6vV5uU4tT3sS2rR1qQ0=")
    token = other_pen.encrypt(b"secret data")

    resp = client.post("/echo", content=token, headers={ENCRYPT_HEADER: "true"})

    assert resp.status_code == 400
