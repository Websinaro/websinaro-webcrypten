import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.django_settings")

import django
django.setup()

import pytest
from django.test import Client

from websinaro.webcrypten import webcryptpen, WebCryptPen


@pytest.fixture
def client():
    return Client()


def test_encrypted_round_trip(client):
    plaintext = b"hello from django client"
    token = webcryptpen.encrypt(plaintext)

    resp = client.post(
        "/echo",
        data=token,
        content_type="text/plain",
        HTTP_X_WEBSINARO_ENCRYPT="true",
    )

    assert resp.status_code == 200
    decrypted_response = webcryptpen.decrypt(resp.content.decode("utf-8"))
    assert decrypted_response == plaintext


def test_unencrypted_request_passes_through(client):
    resp = client.get("/plain")
    assert resp.status_code == 200
    assert resp.json() == {"msg": "not encrypted"}


def test_tampered_token_returns_400(client):
    token = webcryptpen.encrypt(b"hello")
    tampered = token[:10] + ("A" if token[10] != "A" else "B") + token[11:]

    resp = client.post(
        "/echo",
        data=tampered,
        content_type="text/plain",
        HTTP_X_WEBSINARO_ENCRYPT="true",
    )

    assert resp.status_code == 400


def test_wrong_key_cannot_decrypt(client):
    other_pen = WebCryptPen(master_key="ZzZ9xX8yY7wW6vV5uU4tT3sS2rR1qQ0=")
    token = other_pen.encrypt(b"secret data")

    resp = client.post(
        "/echo",
        data=token,
        content_type="text/plain",
        HTTP_X_WEBSINARO_ENCRYPT="true",
    )

    assert resp.status_code == 400