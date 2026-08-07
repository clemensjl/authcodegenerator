# authcodegenerator

Generates auth codes that are easy to read aloud, type, and remember — like
`BOLD-MAPLE-0` instead of `483920`.

Deterministic, stdlib-only, no dependencies.

## Installation

```bash
pip install git+https://github.com/clemensjl/authcodegenerator.git
```

Requires Python 3.9+.

## Usage

Same secret and identifier always give the same code:

```python
>>> from authcodegenerator import generate_auth_code
>>> generate_auth_code("my-secret", "alice@example.com")
'BOLD-MAPLE-0'
>>> generate_auth_code("my-secret", "alice@example.com")
'BOLD-MAPLE-0'
```

A different identifier gives a different code:

```python
>>> generate_auth_code("my-secret", "bob@example.com")
'TOUGH-MOTH-2'
```

Use the optional `counter` to issue several codes for the same identifier
(like an HOTP counter):

```python
>>> generate_auth_code("my-secret", "alice@example.com", counter=1)
'FAST-MIST-5'
>>> generate_auth_code("my-secret", "alice@example.com", counter=2)
'STOIC-CREST-0'
```

Invalid input raises: non-`str` `secret`/`identifier` or non-`int` `counter`
raise `TypeError`, a negative `counter` raises `ValueError`.

## Algorithm

1. Build the message `identifier + b"\x00" + counter` (8-byte big-endian).
2. HMAC-SHA256 it with the secret to get a 32-byte digest.
3. Take three non-overlapping slices of the digest and reduce each modulo its
   alphabet: bytes 0–1 pick an adjective (81 words), bytes 2–3 pick a noun
   (118 words), byte 4 picks a digit (0–9).
4. Join them as `ADJECTIVE-NOUN-DIGIT`.

That is 95,580 possible codes, so it is a memorable *challenge* code,
not a replacement for a high-entropy secret. Keep the secret private — anyone
holding it can compute every code.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```
