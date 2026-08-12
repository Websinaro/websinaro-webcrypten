"""
fastapi_mw.py
FastAPI/Starlette middleware for Websinaro Webcrypten.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from websinaro.webcrypten.utils.exceptions import DecryptionError

ENCRYPT_HEADER = "X-Websinaro-Encrypt"


class WebsinaroMiddleware(BaseHTTPMiddleware):
    """
    Usage:
        from websinaro.webcrypten import webcryptpen
        from websinaro.webcrypten.middleware.fastapi_mw import WebsinaroMiddleware

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

                # Starlette's Request.body() checks the internal `_body` cache
                # FIRST, before ever consulting `_receive` again. Overwriting
                # only `_receive` (without this) silently does nothing, since
                # the cache was already populated by the `await request.body()`
                # call above. Overwrite the cache directly instead.
                request._body = decrypted

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
