"""Starter code for CSC 364 Project 1.

The project is easiest to complete in stages.  Implement and test the small
stateless helpers first, then the handshake, and finally the stateful message
ratchet.  A recommended order is:

1. ``generate_ecdh_key_pair``, public-key parsing, and ``derive_shared_secret``
2. ``hkdf_expand`` and ``ratchet_key``
3. ``encrypt_message`` and ``decrypt_message``
4. ``Party.create_handshake`` and ``Party.establish_session``
5. ``Party.send`` and in-order ``Party.receive``
6. replay rejection and bounded out-of-order delivery
7. negative tests for tampering, identity substitution, and state rollback

Read README.md before implementing a TODO.  It defines exact wire fields,
roles, size limits, and security behavior expected by the tests.

Important security rules:

* Never trust an identity key merely because it appears in a handshake.  It
  must match ``trusted_peer_identity``, which represents an out-of-band pin.
* Never use a raw ECDH secret directly as an AES key; derive purpose-specific
  keys with HKDF.
* Never use a persistent chain key as a message key.  ``ratchet_key`` must
  return two distinct outputs.
* Never update receiving state before AES-GCM authentication succeeds.
* Do not replace precise protocol/authentication exceptions with a broad
  ``except Exception`` handler.
"""

# These imports are intentionally provided even though some remain unused until
# you complete the corresponding TODOs.
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Protocol constants and exact wire schemas
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "CSC364-SecureChat-v2"

# Check attacker-controlled sizes before parsing or allocating large values.
MAX_HANDSHAKE_BYTES = 4096
MAX_PLAINTEXT_BYTES = 1024 * 1024
MAX_SKIP = 100

# These sets are provided so your parser can require exact schemas.  Use
# ``set(parsed_dictionary) == expected_fields`` rather than checking only that
# a few required keys happen to be present.
_HANDSHAKE_PAYLOAD_FIELDS = {
    "version",
    "name",
    "identity_key",
    "ephemeral_key",
    "nonce",
}
_HANDSHAKE_FIELDS = _HANDSHAKE_PAYLOAD_FIELDS | {"signature"}
_HEADER_FIELDS = {"version", "session_id", "direction", "message_number"}


class ProtocolError(ValueError):
    """Malformed input or invalid protocol state, but not failed signatures."""


class AuthenticationError(ProtocolError):
    """Raised when a signed handshake does not match the trusted identity."""


class ReplayError(ProtocolError):
    """Raised when an already-consumed message is received again."""


def _canonical_json(value):
    """Return the one deterministic JSON encoding used by both endpoints.

    Cryptographic operations authenticate bytes.  If Alice signs one JSON
    representation while Bob verifies another representation of the same
    dictionary, verification fails.  Always call this helper for signed
    payloads, complete handshakes, and message-header AAD.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _decode_lower_hex(value, field_name):
    """Decode the exact lowercase hexadecimal representation used on the wire.

    This helper is complete.  Do not replace it with an unchecked
    ``bytes.fromhex`` call: that parser ignores ASCII whitespace, so encoded
    length checks alone do not enforce a decoded byte length.
    """
    if (
        not isinstance(value, str)
        or len(value) % 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProtocolError(f"{field_name} must be lowercase hexadecimal")
    return bytes.fromhex(value)


def _length_prefix(value):
    """Make transcript concatenation unambiguous by prefixing a byte length."""
    return len(value).to_bytes(4, "big") + value


def encode_aad(header):
    """Serialize public header data that AES-GCM must authenticate."""
    return _canonical_json(header)


# ---------------------------------------------------------------------------
# Part 1: ECDH and key derivation
# ---------------------------------------------------------------------------

def generate_ecdh_key_pair():
    """TODO: Return a fresh ``(private_key, public_key)`` on P-384.

    Hints:
    - use ``ec.generate_private_key(ec.SECP384R1())``;
    - derive the public key from the new private key;
    - generate a new pair on every call; and
    - never serialize or transmit the private key.
    """
    
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize an ECDH public key as SubjectPublicKeyInfo PEM.

    This helper is complete.  Notice that a serialized key records its
    algorithm and curve, which you must validate when loading it.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes):
    """Deserialize and validate a P-384 ECDH public key.
    Required checks:
    1. Convert parser ``TypeError``/``ValueError`` failures to ``ProtocolError``.
    2. Require an ``ec.EllipticCurvePublicKey``.
    3. Require the curve to be ``ec.SECP384R1``.

    Parsing a PEM object successfully does *not* prove it is the key type this
    protocol expects.
    """

    try: 
        key = serialization.load_pem_public_key(pem_bytes)
    except (TypeError, ValueError):
        raise ProtocolError

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ProtocolError

    if not isinstance(key.curve, ec.SECP384R1):
        raise ProtocolError

    return key

def derive_shared_secret(private_key, peer_public_key):
    """Validate both P-384 keys and compute their ECDH shared secret.

    Alice's ``private_A.exchange(ECDH, public_B)`` must equal Bob's
    ``private_B.exchange(ECDH, public_A)``.  Return the raw shared bytes for
    HKDF; do not use them directly with AES-GCM.
    """

    validate_private_keys(private_key)
    validate_public_keys(peer_public_key)

    return private_key.exchange(ec.ECDH(), peer_public_key)

def validate_private_keys(private_key):
    """ Validates public keys only """

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError
    
    if not isinstance(private_key.curve, ec.SECP384R1):
        raise ValueError

    return None

def validate_public_keys(public_key):
    """ Validates private keys only """

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError
    
    if not isinstance(public_key.curve, ec.SECP384R1):
        raise ValueError

    return None


def hkdf_expand(secret, info=b"secure chat", salt=None):
    """Derive exactly 32 bytes using HKDF-SHA256.

    Validate that ``secret`` is non-empty bytes, ``info`` is bytes, and ``salt``
    is bytes or ``None``.  Construct a new ``HKDF`` object for every derivation;
    instances from ``cryptography`` are intentionally single use.

    ``info`` is a domain-separation label.  Different purposes (root key,
    direction, next chain, message key) require different labels.
    """
    return HKDF(algorithm=hashes.SHA256(), length = 32, salt = salt, info = info).derive(secret)

def ratchet_key(chain_key):
    """Return ``(next_chain_key, one_time_message_key)``.

    Derive both outputs from the *current* chain key using two distinct HKDF
    ``info`` values:

        CK_i -> next-chain label -> CK_(i+1)  (store this)
        CK_i -> message-key label -> MK_i     (use once, discard)

    Validate that the input is exactly 32 bytes.  The two outputs must be
    deterministic for synchronized peers but different from each other.
    """
    next_chain_key = hkdf_expand(chain_key, info=b"next-chain-key")
    one_time_message_key = hkdf_expand(chain_key, info=b"one-time-message-key")

    return next_chain_key, one_time_message_key


# ---------------------------------------------------------------------------
# Part 2: AES-GCM and defensive message parsing
# ---------------------------------------------------------------------------

def encrypt_message(key, plaintext, aad=None):
    """TODO: Encrypt with AES-256-GCM and a fresh 12-byte nonce.

    Implementation checklist:
    - require a 32-byte key and string plaintext;
    - require AAD to be bytes or ``None``;
    - UTF-8 encode and enforce ``MAX_PLAINTEXT_BYTES``;
    - generate ``os.urandom(12)`` for every call;
    - call ``AESGCM(key).encrypt(nonce, encoded_plaintext, aad)``; and
    - return ``{"nonce": <hex>, "ciphertext": <hex>}``.

    ``AESGCM.encrypt`` appends its 16-byte authentication tag to the returned
    ciphertext.  Do not separate or truncate that tag.
    """
    raise NotImplementedError


def _decode_ciphertext_message(message):
    """TODO: Validate and decode the public nonce/ciphertext fields.

    Before calling ``bytes.fromhex``:
    - require a dictionary;
    - require a string nonce containing exactly 24 lowercase hex characters
      (12 bytes);
    - require an even-length lowercase-hex ciphertext string containing at
      least the 16-byte GCM tag and no more than
      ``MAX_PLAINTEXT_BYTES + 16`` bytes.

    Use ``_decode_lower_hex`` and re-check decoded lengths defensively.  Convert
    malformed encodings to ``ProtocolError``.  Return ``(nonce_bytes,
    ciphertext_and_tag_bytes)``.
    """
    raise NotImplementedError


def decrypt_message(key, message, aad=None):
    """TODO: Validate, authenticate, decrypt, and UTF-8 decode a message.

    Call ``_decode_ciphertext_message`` before AES-GCM.  Let
    ``cryptography.exceptions.InvalidTag`` propagate when the key, nonce,
    ciphertext, tag, or AAD is wrong.  That exception is security-relevant and
    must not be converted into a successful result.

    Decode authenticated plaintext as UTF-8 and convert invalid UTF-8 to a
    ``ProtocolError``.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Part 3: Signed handshake helpers
# ---------------------------------------------------------------------------

def _identity_public_bytes(public_key):
    """Serialize an Ed25519 public key as 32 raw bytes (helper is complete)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _parse_handshake(handshake_bytes):
    """Parse and structurally validate an untrusted handshake.

    This helper does *not* decide whether the peer is trusted; that belongs in
    ``establish_session``.  It should:

    1. enforce ``MAX_HANDSHAKE_BYTES`` before JSON parsing;
    2. require ASCII JSON with exactly ``_HANDSHAKE_FIELDS``;
    3. require string fields, the expected version, and a 1-100 character name;
    4. use ``_decode_lower_hex`` on identity, ephemeral key, nonce, and
       signature;
    5. require 32-byte identity, 16-byte nonce, and 64-byte signature values;
    6. call ``deserialize_public_key`` on the decoded ephemeral PEM; and
    7. return the parsed wire object, unsigned payload, decoded identity,
       validated ECDH public key, and signature.

    Convert syntax/encoding errors to ``ProtocolError``.  Signature verification
    happens later because well-formed input is not necessarily authentic.
    """
    if not isinstance(handshake_bytes, bytes):
        raise ProtocolError("handshake must be bytes")
    
    if len(handshake_bytes) > MAX_HANDSHAKE_BYTES:
        raise ProtocolError("handshake more than MAX_HANDSHAKE_BYTES")
    
    try:
        wire = json.loads(handshake_bytes.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("handshake is not ASCII JSON") from exc
    
    if not isinstance(wire, dict) or set(wire) != _HANDSHAKE_FIELDS:
        raise ProtocolError("handshake must contain exactly the required fields")
    
    if not all(isinstance(value, str) for value in wire.values()):
        raise ProtocolError("handshake fields must be strings")
    
    if _canonical_json(wire) != handshake_bytes:
        raise ProtocolError("handshake is not canonical JSON")
    
    if wire["version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    
    if not 1 <= len(wire["name"]) <= 100:
        raise ProtocolError("name must be 1-100 characters")

    identity = _decode_lower_hex(wire["identity_key"], "identity_key")
    ephemeral_pem = _decode_lower_hex(wire["ephemeral_key"], "ephemeral_key")
    nonce = _decode_lower_hex(wire["nonce"], "nonce")
    signature = _decode_lower_hex(wire["signature"], "signature")

    if len(identity) != 32:
        raise ProtocolError("identity_key must be 32 bytes")
    
    if len(nonce) != 16:
        raise ProtocolError("nonce must be 16 bytes")
    
    if len(signature) != 64:
        raise ProtocolError("signature must be 64 bytes")

    ephemeral_public = deserialize_public_key(ephemeral_pem)
    payload = {field: wire[field] for field in _HANDSHAKE_PAYLOAD_FIELDS}
    return wire, payload, identity, ephemeral_public, signature                                                                                                                


# ---------------------------------------------------------------------------
# Part 4: Stateful participant
# ---------------------------------------------------------------------------

class Party:
    """One participant in the instructional secure-chat protocol.

    State is grouped by lifetime:
    - the Ed25519 identity key persists across sessions;
    - pending ECDH state lives only during one handshake; and
    - sending/receiving chains and counters live for one active session.
    """

    def __init__(self, name, identity_private_key=None):
        # TODO: Before assigning state, require ``name`` to be a non-empty string
        # of at most 100 characters.  If a key is supplied, require an
        # ``ed25519.Ed25519PrivateKey`` and raise ``TypeError`` otherwise.  These
        # checks are part of the public API contract, not merely style.
        if identity_private_key is None:
            identity_private_key = ed25519.Ed25519PrivateKey.generate()

        # Long-term identity state: signing only, never ECDH or AES.
        self.name = name
        self._identity_private_key = identity_private_key
        self._identity_public_key = identity_private_key.public_key()

        # Pending ephemeral handshake state.  Set these in create_handshake and
        # clear them only after establish_session succeeds.
        self._pending_ecdh_private = None
        self._pending_handshake = None

        # Active session state.  Sending and receiving chains advance
        # independently; neither direction may reuse the other's chain.
        self.sending_key = None
        self.receiving_key = None
        self.session_id = None
        self.send_count = 0
        self.receive_count = 0
        self.send_direction = None
        self.receive_direction = None
        # Map message_number -> one-time key for authenticated gaps.  Bound its
        # size by MAX_SKIP and delete an entry after one successful use.
        self._skipped_message_keys = {}

    def get_identity_public_bytes(self):
        """Return the Ed25519 identity that peers must pin out of band.

        In this in-memory simulation, direct access to the intended peer object
        stands in for a trusted QR code, fingerprint, or certificate channel.
        """
        return _identity_public_bytes(self._identity_public_key)

    def create_handshake(self):
        """Create and sign a fresh ephemeral handshake.

        Suggested sequence:
        1. Reject the call if another handshake is already pending.
        2. Generate a fresh P-384 ECDH pair.
        3. Build the five-field payload documented in README.md.  Encode the
           raw identity key and serialized ECDH public key as hexadecimal.
        4. Add a fresh 16-byte random nonce.
        5. Sign ``_canonical_json(payload)`` with the Ed25519 identity key.
        6. Add the hex signature, canonicalize the complete wire object, save
           the private key/wire bytes as pending state, and return the bytes.

        Never sign a non-canonical encoding, never transmit the ECDH private
        key, and never reuse an old pending key for a new session.
        """

        if self._pending_ecdh_private is not None:
            raise ProtocolError("a handshake is already pending")

        ecdh_private, ecdh_public = generate_ecdh_key_pair()

        payload = {
            "version": PROTOCOL_VERSION,
            "name": self.name,
            "identity_key": _identity_public_bytes(self._identity_public_key).hex(),
            "ephemeral_key": serialize_public_key(ecdh_public).hex(),
            "nonce": os.urandom(16).hex(),
        }

        signature = self._identity_private_key.sign(_canonical_json(payload))

        handshake = dict(payload)
        handshake["signature"] = signature.hex()
        wire_bytes = _canonical_json(handshake)

        self._pending_ecdh_private = ecdh_private
        self._pending_handshake = wire_bytes
        return wire_bytes

    def get_public_bytes(self):
        """Backward-compatible alias returning a full signed handshake.

        Despite the historical name, this is not just raw public-key bytes.
        """
        return self.create_handshake()

    def establish_session(
        self,
        peer_handshake_bytes,
        trusted_peer_identity,
        expected_peer_name,
        role="initiator",
    ):
        """Authenticate the handshake and derive directional chains.

        Implement this method in five phases.  Keep all candidate values in
        local variables until phase 5.

        Phase 1 - local preconditions:
        - accept only ``initiator`` and ``responder`` roles;
        - require a pending local handshake/private ECDH key;
        - require a 32-byte ``trusted_peer_identity`` and a 1-100 character
          expected name.

        Phase 2 - peer authentication:
        - parse with ``_parse_handshake``;
        - use ``hmac.compare_digest`` to compare the embedded identity with the
          independently trusted identity;
        - require the signed name to equal ``expected_peer_name``; and
        - reconstruct the Ed25519 public key and verify the signature over
          ``_canonical_json(payload)``.  Convert ``InvalidSignature`` to
          ``AuthenticationError``.

        Phase 3 - common transcript:
        - canonicalize the complete local and peer handshakes;
        - order them *initiator first, responder second* on both endpoints;
        - concatenate a protocol label and the two length-prefixed handshakes;
        - compute SHA-256 of that transcript.

        Phase 4 - secret derivation:
        - perform ECDH with the pending private key and authenticated peer key;
        - derive a transcript-bound root key with HKDF;
        - derive independently labelled initiator-to-responder and
          responder-to-initiator chain keys from the root.

        Phase 5 - atomic commit:
        - derive/store a transcript-bound session ID;
        - assign chains/direction strings according to the local role;
        - reset counters and skipped keys; and
        - clear pending ECDH private state.

        If phases 1-4 fail, the previous active session and pending handshake
        must remain usable.  Trusting the identity key carried in the handshake
        without comparing it to the pinned key is a complete MITM vulnerability.
        """
        # Phase 1: Local preconditions
        # - accept only ``initiator`` and ``responder`` roles;
        # - require a pending local handshake/private ECDH key;
        # - require a 32-byte ``trusted_peer_identity`` and a 1-100 character expected name.

        if role not in ("initiator", "responder"):
            raise ValueError("role is not initiator or responder")
        
        if self._pending_ecdh_private is None or self._pending_handshake is None:
            raise ProtocolError("no pending handshake")
        
        if not isinstance(trusted_peer_identity, bytes):
            raise TypeError("trusted_peer_identity must be bytes")
        
        if len(trusted_peer_identity) != 32:
            raise ValueError("trusted_peer_identity must be 32 bytes")
        
        if not isinstance(expected_peer_name, str):
            raise TypeError("expected_peer_name must be a string")
        
        if not 1 <= len(expected_peer_name) <= 100:
            raise ValueError("expected_peer_name must be 1-100 characters")

        # Phase 2: peer authentication
        #  - parse with ``_parse_handshake``;
        # - use ``hmac.compare_digest`` to compare the embedded identity with the independently trusted identity;
        # - require the signed name to equal ``expected_peer_name``; and
        # - reconstruct the Ed25519 public key and verify the signature over ``_canonical_json(payload)``.  Convert ``InvalidSignature`` to ``AuthenticationError``.
        
        wire, payload, peer_identity, peer_ecdh_public, signature = _parse_handshake(peer_handshake_bytes)

        if not hmac.compare_digest(peer_identity, trusted_peer_identity):
            raise AuthenticationError("handshake identity does not match pinned key")
        
        if payload[self.name] != expected_peer_name:
            raise AuthenticationError("Invalid name for handshake")
        
        peer_identity_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_identity)

        try: 
            peer_identity_key.verify(signature, _canonical_json(json))
        except InvalidSignature as e:
            raise AuthenticationError("Invalid handshake") from e

        # Phase 3: common transcript
        # - canonicalize the complete local and peer handshakes;
        # - order them *initiator first, responder second* on both endpoints;
        # - concatenate a protocol label and the two length-prefixed handshakes;
        # - compute SHA-256 of that transcript

        local_handshake = self._pending_handshake
        peer_handshake = _canonical_json(wire)

        if role == "initiator":
            first, second = local_handshake, peer_handshake
        else:
            first, second = peer_handshake, local_handshake

        transcript = (b"CSC364 authenticated handshake"+ _length_prefix(first)+ _length_prefix(second))

        transcript_hash = hashlib.sha256(transcript).digest()

        # Phase 4: secret derivation
        # - perform ECDH with the pending private key and authenticated peer key;
        # - derive a transcript-bound root key with HKDF;
        # - derive independently labelled initiator-to-responder and responder-to-initiator chain keys from the root.

        shared_secret = derive_shared_secret(self._pending_ecdh_private, peer_ecdh_public)

        root_key = hkdf_expand(shared_secret, info=b"CSC364-v2 root key" + transcript_hash, salt=transcript_hash)

        initiator_to_responder = hkdf_expand(root_key, info=b"CSC364-v2 initiator-to-responder chain" + transcript_hash, salt=transcript_hash)

        responder_to_initiator = hkdf_expand(root_key, info=b"CSC364-v2 responder-to-initiator chain" + transcript_hash, salt=transcript_hash)

        session_id = hashlib.sha256(b"CSC364-v2 session id" + transcript_hash).hexdigest()

        # Phase 5: atomic commit
        # - derive/store a transcript-bound session ID;
        # - assign chains/direction strings according to the local role;
        # - reset counters and skipped keys; and
        # - clear pending ECDH private state.

        if role == "initiator":
            self.sending_key = initiator_to_responder
            self.receiving_key = responder_to_initiator
            self.send_direction = "initiator-to-responder"
            self.receive_direction = "responder-to-initiator"
        else:
            self.sending_key = responder_to_initiator
            self.receiving_key = initiator_to_responder
            self.send_direction = "responder-to-initiator"
            self.receive_direction = "initiator-to-responder"

        self.session_id = session_id
        self.send_count = 0
        self.receive_count = 0
        self._skipped_message_keys = {}
        self._pending_ecdh_private = None
        self._pending_handshake = None

    def send(self, plaintext):
        """TODO: Encrypt one message and advance the sending chain.

        Checklist:
        1. Require an established session.
        2. Build the exact four-field header using the current send counter.
        3. Derive ``(candidate_next_chain, message_key)``.
        4. Encrypt with the message key and ``encode_aad(header)``.
        5. Attach the public header to the returned message.
        6. Only now commit the candidate chain and increment the counter.

        Do not store ``message_key`` on ``self``.  It should become unreachable
        when the method returns.
        """
        raise NotImplementedError

    def receive(self, msg):
        """TODO: Authenticate one message and advance the receiving chain.

        Start by requiring an active session and validating the exact outer and
        header schemas.  Check version, session ID, direction, and a non-negative
        integer message number before doing KDF work.  The header must still be
        used as AES-GCM AAD; pre-checking it is not a substitute for cryptographic
        authentication.

        Handle three number ranges:

        - ``number < receive_count``: look up a retained skipped key.  Missing
          means the message was already consumed, so raise ``ReplayError``.
        - ``number == receive_count``: derive one normal ratchet step.
        - ``number > receive_count``: derive forward to the target while saving
          keys for missing numbers.  Reject if new plus existing skipped keys
          would exceed ``MAX_SKIP``.

        For the latter two cases, derive into local candidate variables.  Call
        ``decrypt_message`` before assigning ``receiving_key``, incrementing
        ``receive_count``, or merging skipped keys.  For an older skipped
        message, delete its stored key only after successful authentication.

        This validate-then-commit structure is what prevents a forged packet
        from permanently desynchronizing Alice and Bob.
        """
        raise NotImplementedError


def simulate_chat():
    """TODO: Demonstrate an authenticated bidirectional session.

    Create Alice and Bob, call ``create_handshake`` once on each, establish the
    two sides with pinned identity bytes and opposite roles, then exchange at
    least two Alice-to-Bob messages and one Bob-to-Alice reply.  Print encrypted
    wire dictionaries and successfully recovered plaintexts, but never print
    private, root, chain, or message keys.
    """
    raise NotImplementedError


if __name__ == "__main__":
    simulate_chat()
