import os
os.environ.setdefault("MASTER_KEY", "Xk9pQ2vN8mL4wR7tY1zA6bC3dF5gH0jK+/==")

SECRET_KEY = "test-secret-key-not-for-production"
DEBUG = True
ALLOWED_HOSTS = ["testserver"]
ROOT_URLCONF = "tests.django_urls"
MIDDLEWARE = [
    "websinaro.middleware.django_mw.WebsinaroMiddleware",
]
DATABASES = {}