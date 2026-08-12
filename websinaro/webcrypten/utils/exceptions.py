"""
exceptions.py
Custom exception types for Websinaro Webcrypten.
"""


class WebsinaroError(Exception):
    """Base exception for all Websinaro Webcrypten errors."""
    pass


class SmallKeyError(WebsinaroError):
    pass


class NotStandardFormError(WebsinaroError):
    pass


class KeyLoadError(WebsinaroError):
    pass


class DecryptionError(WebsinaroError):
    pass
