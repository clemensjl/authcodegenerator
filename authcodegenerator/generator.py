"""
Easy-to-remember auth code generator.

Algorithm
---------
1. Derive a 32-byte HMAC-SHA256 digest from the caller-supplied *secret* and
   *identifier* (e.g. a username, email, or session token).
2. Take three non-overlapping slices of the digest -- bytes 0-1, bytes 2-3, and
   byte 4 -- and reduce each modulo the length of the corresponding word list
   (adjectives, nouns) or the digit range (0-9) to select a component.
3. Join the three components with a hyphen: ``ADJECTIVE-NOUN-DIGIT``.

The result is:

* **Deterministic** – identical inputs always produce the same code.
* **Unpredictable** – without the secret, an attacker cannot pre-compute codes.
* **Human-readable** – the word + digit format is easy to read aloud, type,
  and remember (e.g. ``SWIFT-MAPLE-4``).

Counter support
~~~~~~~~~~~~~~~
An optional *counter* argument (default ``0``) is appended to the identifier
before hashing so that you can issue multiple distinct codes for the same
identifier (like HOTP counters).
"""

import hmac
import hashlib
import struct
# ---------------------------------------------------------------------------
# Word lists – chosen to be short, unambiguous, and easily pronounceable.
# ---------------------------------------------------------------------------

_ADJECTIVES: tuple[str, ...] = (
    "AMBER",
    "AZURE",
    "BOLD",
    "BRAVE",
    "BRIGHT",
    "BRISK",
    "CALM",
    "CHIEF",
    "CLEAN",
    "CLEAR",
    "CRISP",
    "DARK",
    "DEEP",
    "DENSE",
    "DULL",
    "EPIC",
    "FAIR",
    "FAST",
    "FINE",
    "FIRM",
    "FLEET",
    "FRANK",
    "FREE",
    "FRESH",
    "FROSTY",
    "GLAD",
    "GOLD",
    "GRAND",
    "GRAVE",
    "GREAT",
    "GREEN",
    "GREY",
    "HARDY",
    "HIGH",
    "IRON",
    "KEEN",
    "KIND",
    "LARGE",
    "LIGHT",
    "LIVE",
    "LONG",
    "LOUD",
    "LOYAL",
    "NOBLE",
    "PALE",
    "PLAIN",
    "PROUD",
    "PURE",
    "QUICK",
    "QUIET",
    "RAPID",
    "READY",
    "RED",
    "RICH",
    "ROUND",
    "ROYAL",
    "SHARP",
    "SHINY",
    "SHORT",
    "SLIM",
    "SMART",
    "SOLID",
    "STARK",
    "STIFF",
    "STILL",
    "STOIC",
    "STOUT",
    "SUNNY",
    "SWIFT",
    "TALL",
    "TAME",
    "TIDY",
    "TOUGH",
    "TRIM",
    "TRUE",
    "VAST",
    "VIVID",
    "WARM",
    "WIDE",
    "WILD",
    "WISE",
)

_NOUNS: tuple[str, ...] = (
    "APPLE",
    "ARCH",
    "ARROW",
    "ASH",
    "ATLAS",
    "AXE",
    "BARK",
    "BEAM",
    "BEAR",
    "BIRCH",
    "BLADE",
    "BLOOM",
    "BOLT",
    "BRIDGE",
    "BROOK",
    "CAVE",
    "CEDAR",
    "CLIFF",
    "CLOUD",
    "COAST",
    "COMET",
    "CORAL",
    "CRANE",
    "CREEK",
    "CREST",
    "CROWN",
    "DALE",
    "DAWN",
    "DEER",
    "DELTA",
    "DOVE",
    "DRIFT",
    "DUNE",
    "EAGLE",
    "ELK",
    "ELM",
    "EMBER",
    "FERN",
    "FIELD",
    "FJORD",
    "FLAME",
    "FLINT",
    "FORD",
    "FORGE",
    "FROST",
    "GALE",
    "GLADE",
    "GLEN",
    "GLYPH",
    "GROVE",
    "HAWK",
    "HEATH",
    "HELM",
    "HILL",
    "IRIS",
    "ISLE",
    "IVY",
    "JADE",
    "KITE",
    "LAKE",
    "LANCE",
    "LARK",
    "LEAF",
    "LEDGE",
    "LINDEN",
    "LION",
    "LYNX",
    "MAPLE",
    "MARSH",
    "MESA",
    "MIST",
    "MOON",
    "MOSS",
    "MOTH",
    "MOUND",
    "OAK",
    "OPAL",
    "ORCA",
    "OTTER",
    "PEAK",
    "PINE",
    "POND",
    "QUARTZ",
    "RAVEN",
    "REEF",
    "RIDGE",
    "RIVER",
    "ROBIN",
    "ROCK",
    "ROSE",
    "RUNE",
    "SAGE",
    "SAND",
    "SEA",
    "SHALE",
    "SHORE",
    "SLATE",
    "SNOW",
    "SOLAR",
    "SPARK",
    "SPIRE",
    "SPRUCE",
    "STAR",
    "STEM",
    "STONE",
    "STORM",
    "SWAN",
    "TIDE",
    "TIGER",
    "TIMBER",
    "TORCH",
    "TRAIL",
    "VALE",
    "VINE",
    "VIPER",
    "VISTA",
    "WAVE",
    "WREN",
)


def generate_auth_code(
    secret: str,
    identifier: str,
    counter: int = 0,
) -> str:
    """Return an easy-to-remember auth code for the given *identifier*.

    Parameters
    ----------
    secret:
        A private string shared between the issuer and verifier.  Treat it
        like a password – never expose it in logs or error messages.
    identifier:
        A per-user or per-session value (e.g. username or email address) that
        makes each code unique to a principal.
    counter:
        An optional integer counter (default ``0``).  Incrementing the counter
        produces a different code for the same ``(secret, identifier)`` pair,
        similar to the HOTP counter mechanism.

    Returns
    -------
    str
        A code of the form ``ADJECTIVE-NOUN-DIGIT``, e.g. ``SWIFT-MAPLE-4``.

    Raises
    ------
    TypeError
        If *secret*, *identifier*, or *counter* have unexpected types.
    ValueError
        If *counter* is negative.
    """
    if not isinstance(secret, str):
        raise TypeError(f"secret must be str, got {type(secret).__name__}")
    if not isinstance(identifier, str):
        raise TypeError(f"identifier must be str, got {type(identifier).__name__}")
    if not isinstance(counter, int):
        raise TypeError(f"counter must be int, got {type(counter).__name__}")
    if counter < 0:
        raise ValueError(f"counter must be >= 0, got {counter}")

    # Build the message: identifier + null separator + big-endian counter
    msg = identifier.encode() + b"\x00" + struct.pack(">Q", counter)

    # Derive a 32-byte digest
    digest = hmac.new(secret.encode(), msg, hashlib.sha256).digest()

    # Pick components from non-overlapping 2-byte windows of the digest
    adj_idx = struct.unpack_from(">H", digest, 0)[0] % len(_ADJECTIVES)
    noun_idx = struct.unpack_from(">H", digest, 2)[0] % len(_NOUNS)
    digit = digest[4] % 10

    return f"{_ADJECTIVES[adj_idx]}-{_NOUNS[noun_idx]}-{digit}"
