"""
django_mw.py
Django middleware for Websinaro.
"""

from django.http import JsonResponse

from websinaro.webcrypten.utils.exceptions import DecryptionError

ENCRYPT_HEADER = "HTTP_X_WEBSINARO_ENCRYPT"  # Django prefixes custom headers with HTTP_


class WebsinaroMiddleware:
    """
    Usage (settings.py):
        MIDDLEWARE = [
            ...,
            "websinaro.middleware.django_mw.WebsinaroMiddleware",
        ]

        # Django middleware is class-based and instantiated by the framework,
        # so the webcryptpen instance is imported directly rather than passed in.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        from websinaro import webcryptpen
        self._wcp = webcryptpen

    def __call__(self, request):
        is_encrypted = request.META.get(ENCRYPT_HEADER, "").lower() == "true"

        if is_encrypted and request.body:
            try:
                token = request.body.decode("utf-8")
                decrypted = self._wcp.decrypt(token)
            except (DecryptionError, UnicodeDecodeError) as e:
                return JsonResponse({"error": f"Decryption failed: {e}"}, status=400)

            request._body = decrypted  # Django caches body here

        response = self.get_response(request)

        if is_encrypted:
            token = self._wcp.encrypt(response.content)
            response.content = token
            response["Content-Type"] = "text/plain"
            response[ENCRYPT_HEADER] = "true"

        return response