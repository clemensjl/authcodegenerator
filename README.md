# authcodegenerator

Generates Auth Codes using a self-developed easy-to-remember algorithm.

## Algorithm

The algorithm produces codes of the form **`ADJECTIVE-NOUN-DIGIT`**
(e.g. `SWIFT-MAPLE-4`):

1. An [HMAC-SHA256](https://en.wikipedia.org/wiki/HMAC) digest is derived from
   the caller-supplied **secret** and **identifier** (e.g. username or email),
   with an optional integer **counter** appended to support multiple codes per
   principal (similar to [HOTP](https://en.wikipedia.org/wiki/HMAC-based_one-time_password)).
2. Three non-overlapping 2-byte windows of the digest are each reduced modulo
   the length of the corresponding word list (adjectives, nouns) or digit range
   (0–9).
3. The three components are joined with hyphens to form the final code.

Properties:

| Property | Details |
|---|---|
| **Deterministic** | Same `(secret, identifier, counter)` → same code |
| **Unpredictable** | Without the secret an attacker cannot pre-compute codes |
| **Human-readable** | Short common words + single digit – easy to read aloud and remember |

## Installation

```bash
pip install .
```

Requires Python ≥ 3.11.

## Usage

```python
from authcodegenerator import generate_auth_code

# Basic usage
code = generate_auth_code("my-secret", "alice@example.com")
# e.g. "BOLD-MAPLE-0"

# With a counter (issue multiple codes for the same principal)
code_0 = generate_auth_code("my-secret", "alice@example.com", counter=0)
code_1 = generate_auth_code("my-secret", "alice@example.com", counter=1)
```

## Running the tests

```bash
pip install ".[dev]"
python -m pytest
```
