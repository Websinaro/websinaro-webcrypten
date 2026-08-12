import os
os.environ["MASTER_KEY"] = "Xk9pQ2vN8mL4wR7tY1zA6bC3dF5gH0jK+/=="

import pytest
from flask import Flask, jsonify, g

from websinaro.webcrypten import webcryptpen
from websinaro.webcrypten.middleware.flask_mw import init_app, ENCRYPT_HEADER


@pytest.fixture
def app():
    app = Flask(__name__)
    init_app(app, webcryptpen_instance=webcryptpen)

    @app.route("/echo", methods=["POST"])
    def echo():
        # Handler reads decrypted body via g, set by the middleware
        decrypted = g.decrypted_body
        return decrypted, 200  # echo raw bytes back; after_request will re-encrypt

    @app.route("/plain", methods=["GET"])
    def plain():
        return "not encrypted", 200

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_encrypted_round_trip(client):
    plaintext = b"hello from the client"
    token = webcryptpen.encrypt(plaintext)

    resp = client.post(
        "/echo",
        data=token,
        headers={ENCRYPT_HEADER: "true"},
    )

    assert resp.status_code == 200
    assert resp.headers.get(ENCRYPT_HEADER) == "true"

    # Response body is itself an encrypted token — decrypt it to verify
    decrypted_response = webcryptpen.decrypt(resp.get_data(as_text=True))
    assert decrypted_response == plaintext


def test_unencrypted_request_passes_through(client):
    resp = client.get("/plain")
    assert resp.status_code == 200
    assert resp.get_data(as_text=True) == "not encrypted"
    assert ENCRYPT_HEADER not in resp.headers


def test_tampered_token_returns_400(client):
    plaintext = b"hello"
    token = webcryptpen.encrypt(plaintext)

    # Flip a character in the middle of the base64 token to corrupt it
    tampered = token[:10] + ("A" if token[10] != "A" else "B") + token[11:]

    resp = client.post(
        "/echo",
        data=tampered,
        headers={ENCRYPT_HEADER: "true"},
    )

    assert resp.status_code == 400


def test_wrong_key_cannot_decrypt(client):
    from websinaro import WebCryptPen
    other_pen = WebCryptPen(master_key="ZzZ9xX8yY7wW6vV5uU4tT3sS2rR1qQ0=")
    token = other_pen.encrypt(b"secret data")

    resp = client.post(
        "/echo",
        data=token,
        headers={ENCRYPT_HEADER: "true"},
    )

    assert resp.status_code == 400