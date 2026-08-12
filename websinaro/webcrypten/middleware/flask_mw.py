"""
flask_mw.py
Flask middleware for Websinaro Webcrypten: transparently decrypts incoming
request bodies and encrypts outgoing response bodies when the encryption
header is present.
"""

import io

from flask import request, g, abort
from websinaro.webcrypten.utils.exceptions import DecryptionError

ENCRYPT_HEADER = "X-Websinaro-Encrypt"


def init_app(app, webcryptpen_instance):
    """
    Wires Websinaro Webcrypten into a Flask app.

    Usage:
        from websinaro.webcrypten import webcryptpen
        from websinaro.webcrypten.middleware.flask_mw import init_app

        app = Flask(__name__)
        init_app(app, webcryptpen_instance=webcryptpen)
    """

    @app.before_request
    def _decrypt_incoming():
        if request.headers.get(ENCRYPT_HEADER, "").lower() != "true":
            return  # not encrypted, pass through untouched

        raw_body = request.get_data()
        if not raw_body:
            return

        try:
            token = raw_body.decode("utf-8")
            decrypted = webcryptpen_instance.decrypt(token)
        except (DecryptionError, UnicodeDecodeError) as e:
            abort(400, description=f"Decryption failed: {e}")

        # Stash decrypted body so route handlers can access it via g.decrypted_body
        g.decrypted_body = decrypted
        # Overwrite Flask's internal cache so request.get_data()/get_json() see plaintext
        request._cached_data = decrypted
        request.environ["wsgi.input"] = io.BytesIO(decrypted)

    @app.after_request
    def _encrypt_outgoing(response):
        if request.headers.get(ENCRYPT_HEADER, "").lower() != "true":
            return response

        plaintext_body = response.get_data()
        token = webcryptpen_instance.encrypt(plaintext_body)
        response.set_data(token)
        response.headers["Content-Type"] = "text/plain"
        response.headers[ENCRYPT_HEADER] = "true"
        return response
