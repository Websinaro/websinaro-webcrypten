"""
fastapi_mw.py
FastAPI/Starlette middleware for Websinaro.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from websinaro.webcrypten.utils.exceptions import DecryptionError

ENCRYPT_HEADER = "X-Websinaro-Encrypt"


class WebsinaroMiddleware(BaseHTTPMiddleware):
    """
    Usage:
        from websinaro import webcryptpen
        from websinaro.middleware.fastapi_mw import WebsinaroMiddleware

        app.add_middleware(WebsinaroMiddleware, webcryptpen_instance=webcryptpen)
    """

    def __init__(self, app, webcryptpen_instance):
        super().__init__(app)
        self._wcp = webcryptpen_instance

    async def dispatch(self, request: Request, call_next):
        is_encrypted = request.headers.get(ENCRYPT_HEADER, "").lower() == "true"

        if is_encrypted:
            raw_body = await request.body()
            if raw_body:
                try:
                    token = raw_body.decode("utf-8")
                    decrypted = self._wcp.decrypt(token)
                except (DecryptionError, UnicodeDecodeError) as e:
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Decryption failed: {e}"},
                    )

                # Replace the request's receive() so downstream handlers
                # see decrypted bytes when they call request.body()/.json()
                async def receive():
                    return {"type": "http.request", "body": decrypted, "more_body": False}
                request._receive = receive

        response = await call_next(request)

        if is_encrypted:
            body_chunks = [chunk async for chunk in response.body_iterator]
            plaintext_body = b"".join(body_chunks)
            token = self._wcp.encrypt(plaintext_body)

            new_response = Response(
                content=token,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type="text/plain",
            )
            new_response.headers[ENCRYPT_HEADER] = "true"
            return new_response

        return response