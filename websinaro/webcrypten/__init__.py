"""
websinaro/__init__.py
Public entry point: from websinaro import webcryptpen, WebCryptPen
"""

from websinaro.webcryptpen.core.engine import WebCryptPen

__all__ = ["WebCryptPen", "webcryptpen"]

_singleton = None


def __getattr__(name: str):
    """
    PEP 562 module-level __getattr__ — lets `webcryptpen` behave like a
    plain attribute to callers, while deferring actual instantiation
    (and the env-var/key validation it triggers) until first access.
    """
    global _singleton
    if name == "webcryptpen":
        if _singleton is None:
            _singleton = WebCryptPen()
        return _singleton
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")