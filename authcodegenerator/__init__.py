"""
authcodegenerator – generates easy-to-remember authentication codes.

The algorithm is deterministic: the same (secret, identifier) pair always
produces the same code, making it useful for TOTP-style or challenge-response
flows where both sides share the secret.

Usage::

    from authcodegenerator import generate_auth_code
    code = generate_auth_code("my-secret", "alice@example.com")
    # e.g. "SWIFT-MAPLE-4"
"""

from authcodegenerator.generator import generate_auth_code

__all__ = ["generate_auth_code"]
