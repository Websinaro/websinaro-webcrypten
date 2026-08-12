# websinaro-webcrypten


```markdown
# Websinaro Webcrypten

Two-level (double-cipher chained) encryption middleware for Python web frameworks.

Websinaro Webcrypten encrypts data through two independent authenticated
ciphers — **AES-256-GCM** followed by **ChaCha20-Poly1305** — using two
cryptographically independent keys derived via HKDF from a single master
key. If either cipher is ever weakened, the other layer still protects
your data.

Built-in middleware for **Flask**, **FastAPI**, and **Django** transparently
encrypts/decrypts HTTP request and response bodies with zero changes to
your route handlers.

## Installation

```bash
pip install websinaro-webcrypten
```

## Quick start

```python
from websinaro.webcrypten import webcryptpen

token = webcryptpen.encrypt("hello world")
plaintext = webcryptpen.decrypt(token)

print(plaintext)  # b"hello world"
```

`webcryptpen` is a ready-to-use singleton. It reads its master key from
the `MASTER_KEY` environment variable on first use.

```bash
export MASTER_KEY="$(openssl rand -base64 32)"
```

### Using your own key instance

```python
from websinaro.webcrypten import WebCryptPen

pen = WebCryptPen(master_key="your-generated-key-here")
token = pen.encrypt(b"sensitive data")
plaintext = pen.decrypt(token)
```

## How it works

```
plaintext
  -> AES-256-GCM encrypt        (key1, random nonce)
  -> ChaCha20-Poly1305 encrypt  (key2, random nonce)
  -> base64(version_byte + nonce1 + nonce2 + final_ciphertext)
```

- `key1` and `key2` are derived from your master key via **HKDF-SHA256**
  with distinct labels — they are cryptographically independent of each
  other, never reused, and never stored.
- Every encryption call generates fresh random nonces — encrypting the
  same plaintext twice never produces the same ciphertext.
- Both layers are **authenticated** (GCM / Poly1305) — any tampering with
  the ciphertext causes decryption to fail loudly, never silently return
  corrupted data.
- Decryption failures (wrong key, tampered data, corrupted envelope) all
  raise `websinaro.webcrypten.utils.exceptions.DecryptionError` — the
  error message never reveals *which* layer or *why* it failed, to avoid
  leaking information to an attacker probing your system.

## Master key requirements

Your master key must be:

- At least 32 characters
- Base64 or hex-safe characters only

Generate one with:
```bash
openssl rand -base64 32
```
or in Python:
```python
import secrets
secrets.token_urlsafe(32)
```

**Do not** use a human-typed password as your master key — this library
is designed for machine-generated, high-entropy secrets, not
password-based key derivation.

## Middleware usage

All middleware share the same behavior: requests/responses are only
encrypted/decrypted when the `X-Websinaro-Encrypt: true` header is
present, so you can mix encrypted and plain endpoints freely.

### Flask

```python
from flask import Flask
from websinaro.webcrypten import webcryptpen
from websinaro.webcrypten.middleware.flask_mw import init_app

app = Flask(__name__)
init_app(app, webcryptpen_instance=webcryptpen)

@app.route("/secure", methods=["POST"])
def secure_endpoint():
    from flask import g
    data = g.decrypted_body   # already decrypted by the middleware
    return b"response data"    # automatically encrypted before it's sent
```

### FastAPI

```python
from fastapi import FastAPI
from websinaro.webcrypten import webcryptpen
from websinaro.webcrypten.middleware.fastapi_mw import WebsinaroMiddleware

app = FastAPI()
app.add_middleware(WebsinaroMiddleware, webcryptpen_instance=webcryptpen)

@app.post("/secure")
async def secure_endpoint(request):
    data = await request.body()   # already decrypted
    return b"response data"
```

### Django

`settings.py`:
```python
MIDDLEWARE = [
    # ... your other middleware ...
    "websinaro.webcrypten.middleware.django_mw.WebsinaroMiddleware",
]
```

Route handlers read `request.body` as usual — it's already decrypted by
the time your view runs; the response is automatically re-encrypted.

## Exceptions

| Exception | Raised when |
|---|---|
| `KeyLoadError` | `MASTER_KEY` env var missing and no key passed explicitly |
| `SmallKeyError` | Master key is under 32 characters |
| `NotStandardFormError` | Master key contains invalid characters, or isn't a string |
| `DecryptionError` | Decryption fails — wrong key, tampered data, corrupted or unsupported envelope format |

All inherit from `websinaro.webcrypten.utils.exceptions.WebsinaroError`.

## Security notes

- Rotating the master key requires creating a new `WebCryptPen` instance
  with the new key — existing tokens encrypted under the old key cannot
  be decrypted by an instance holding only the new key. Keep the old key
  available during any rotation transition window.
- Never commit your `MASTER_KEY` to source control. Use environment
  variables, a secrets manager, or your platform's equivalent.
- This library depends on the [`cryptography`](https://cryptography.io)
  package, which requires a platform with prebuilt wheels (standard
  Linux/macOS/Windows CPython, Docker). It is **not compatible** with
  constrained environments like Pydroid on Android.

## Development

```bash
git clone https://github.com/<your-username>/websinaro-webcrypten.git
cd websinaro-webcrypten
pip install -e .
pip install pytest flask fastapi uvicorn django httpx mypy ruff

export MASTER_KEY="$(openssl rand -base64 32)"
pytest tests/ -v
```

## License

MIT License — see LICENSE file.
```

---

## `LICENSE` (MIT — replace `<Your Name / Websinaro>` and year as needed)

```
MIT License

Copyright (c) 2026 Websinaro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

```
