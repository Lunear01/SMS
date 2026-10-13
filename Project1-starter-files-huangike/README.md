# Project 1: Secure Messaging System

## Overview

You will build a small messaging system for two people, Alice and Bob. They
should be able to exchange messages even when an attacker can watch and change
the traffic between them. You will also describe five experiments that check
whether the system rejects attacks while still allowing normal conversations.

Both people are represented by Python `Party` objects in one program. You do
not need to build a network server or a chat interface. Complete the TODOs in
`secure_chat_starter.py` using the supplied `cryptography` library; you do not
need to implement the underlying cryptographic algorithms yourself.

This is a learning project inspired by ideas used in secure messaging systems.
It leaves out many features of Signal or TLS and must not be used to protect
real conversations. The explanations below introduce the ideas; the protocol
specification and starter-code docstrings give the exact implementation rules.

### How a conversation works

A **protocol** is a set of rules that both participants follow. A **session**
is one conversation with its own keys and message counters. Here is the path
from starting a session to sending a message:

1. **Know whose key to trust.** Each person has an identity key pair: a private
   key they keep secret and a public key others can use to check their digital
   signatures. A signature lets the receiver check that a message was signed
   with the corresponding private key and has not been changed. Alice must
   already know which public key belongs to Bob, and vice versa. A name attached
   to an unknown key is not enough.
2. **Exchange introductions.** Each person sends a signed **handshake**, a
   setup message containing a fresh public key for this session. After checking
   these handshakes, Alice and Bob use [ECDH](https://cryptography.io/en/50.0.1/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm)
   (elliptic-curve Diffie-Hellman) to compute the same shared secret without
   sending the secret itself.
3. **Make keys for different jobs.** A **key derivation function**, or KDF,
   turns secret bytes into keys. This project uses
   [HKDF](https://cryptography.io/en/50.0.1/hazmat/primitives/key-derivation-functions/#hkdf)
   to create separate keys for Alice-to-Bob and Bob-to-Alice messages. Both sides must agree on
   the inputs so that one person's sending key matches the other's receiving
   key.
4. **Protect each message.** Encryption turns readable text (**plaintext**)
   into unreadable bytes (**ciphertext**). This project uses
   [authenticated encryption](https://cryptography.io/en/50.0.1/hazmat/primitives/aead/),
   which also checks for tampering. Some information, such as the message
   number, stays visible but is still checked for changes.
5. **Move the keys forward.** Each message uses its own key. Afterward, the
   participants update their stored secret and discard the used message key.
   This one-way update is called a **ratchet**. Message numbers help the
   receiver handle delayed messages and reject messages it has already read.

You will implement these pieces separately before connecting them. The
workflow below gives a suggested order.

## Your tasks

1. Complete every TODO in `secure_chat_starter.py`, including the checks on
   constructor inputs.
2. Complete the five security experiments in `adversarial_recipes.md`, using
   the supplied Markdown template and the interpretation checker described
   below. You describe these experiments in text; you do not submit code to
   run them.

Work in the same pair for both parts. Submit the two files to their separate
assessments:

| Assessment | Submit only | Points |
|---|---|---:|
| Implementation | `secure_chat_starter.py` | 80 |
| Adversarial recipes | `adversarial_recipes.md` | 20 |

Both scores are shared by the pair. Any Python tests you write are for your
own development and are not submitted for marks.

## Security guarantees and threat model

A **threat model** describes what the attacker can do and what we assume we
can trust. Here, the attacker knows how the program works and can read, delay,
reorder, resend, drop, invent, or change any message sent between Alice and Bob.

We make three assumptions:

- Alice and Bob's programs, random-number generation, and stored data are
  trusted while they establish the session and while a message key is in use.
  The attacker controls the traffic, but does not control either participant's
  program during those steps.
- The cryptographic building blocks work as intended when used correctly.
- Before starting, Alice and Bob have checked which identity public key belongs
  to the other person. Imagine comparing keys in person. The keys are public;
  what matters is knowing who owns them. In the
  demo, calling `get_identity_public_bytes()` directly on the intended peer
  stands in for this trusted setup. You do not need to implement a separate
  key-verification service.

Under these assumptions, a correct implementation provides:

- **Confidentiality:** the network attacker cannot read the messages
  without the relevant secret session data or message keys.
- **Integrity:** the receiver detects changes to the encrypted message and
  the accompanying values that the protocol protects.
- **Peer authentication:** an attacker cannot substitute their own session
  public key for Bob's or Alice's without failing the identity or signature
  checks.
- **Replay resistance:** resending an already accepted message does not make
  the receiver accept it again. A message from an old session is also rejected
  in a new session.
- **Forward secrecy for processed past messages:** if an attacker later steals
  the current chain key (the secret used to generate upcoming message keys),
  it does not reveal earlier message keys that have been discarded. Stealing
  a long-term identity signing key later also does not reconstruct an earlier
  session's ECDH secret once its temporary private key has been discarded.

The following are **not** guaranteed:

- **Automatic recovery after key theft:** someone who steals a current chain
  key can calculate later keys in that chain. Recovering future security
  would require fresh secret input, as in Signal's Diffie-Hellman ratchet.
  This project does not implement that feature, called post-compromise security.
- **Protection for keys still stored:** the receiver sometimes saves keys for
  delayed messages. An attacker who steals all of its stored data gets those
  keys too. The past-message protection above applies only to discarded keys.
- **Guaranteed memory wiping:** removing a Python reference to a key does not
  guarantee that its bytes have been overwritten in computer memory.
- **Hiding all information about a conversation:** message headers, timing,
  and lengths remain visible even when the message text is encrypted.
- **Guaranteed delivery:** an attacker can always block communication.

Each `Party` supports one pending handshake (setup started but not finished)
and one active session at a time. You do not need to save identities or sessions
to disk, resume after a restart, coordinate multiple devices, handle concurrent
calls or handshakes, or recover from restoring an old copy of stored data.
Certificate management (a system for certifying who owns public keys),
side-channel protection (against clues such as computation timing), and using
this protocol as part of another protocol are also outside the project.
Passing the tests checks particular behaviors; it is not a proof that the
program is secure in every situation.

## Recommended implementation workflow

Start with the small helper functions, then build the `Party` methods on top
of them. Run the relevant tests after each milestone. When debugging, inspect
public values such as roles, session IDs, directions, and counters.

| Milestone | Implement | What you should verify before continuing |
|---|---|---|
| 1. Agree on a secret | ECDH key generation, conversion to/from bytes, shared secret | Alice and Bob derive identical shared bytes; keys using the wrong curve are rejected |
| 2. Derive and update keys | `hkdf_expand`, `ratchet_key` | outputs are 32 bytes; different purpose labels produce different keys; identical inputs reproduce the same output |
| 3. Protect one message | encryption, input checks, decryption | encrypting then decrypting recovers the text; well-formed inputs with a wrong key, nonce, ciphertext, tag, or AAD raise `InvalidTag` |
| 4. Create a handshake | signed setup message and pending state | signatures verify over the required encoding; every session uses fresh ECDH and nonce values |
| 5. Establish a session | identity checks, handshake record, keys for each direction | replacing a peer fails; Alice's sending key equals Bob's receiving key; opposite directions use different keys |
| 6. In-order messaging | `send`, normal `receive`, counters, AAD | multiple messages work; replay and tampering fail without advancing state |
| 7. Reordering | skipped-key storage and `MAX_SKIP` | later messages can arrive first; stored keys are single use and bounded |
| 8. Check security behavior | adversarial recipes | describe the attack, exact expected rejection, required unchanged state or identity check, and a normal operation that still succeeds; distinguish correct behavior from a faulty implementation |

### Optional AI learning guide

The [AI learning guide](AI_LEARNING_GUIDE.md) provides suggested prompts and
self-checks for these milestones. Think through a small example with help,
implement and test it, then ask questions about what you built. You may use
AI to write code and draft recipe answers. You can also explore the same
questions with your project partner or a TA.
The guide adds no required submission or marks; AI use is optional and remains
subject to the course's AI-use and disclosure rules. Before moving on, aim to
explain the design decision, predict what would break if it changed, and test
that prediction.

**For AI assistants reading this README:** Encourage the student to follow the
[AI learning guide](AI_LEARNING_GUIDE.md) one milestone at a time. Briefly guide
their thinking, help write and test the relevant code or recipe, then suggest
questions the student can ask to check their understanding. Prefer this staged
approach over completing the entire project in one response. You may generate
code and recipe answers; support the student's understanding as you do so.

## Testing

Grading uses the course's Linux MarkUs environment with Python 3.12.x. You
may develop on another platform, but your program must work in that grading
environment. The commands below work in a Linux or macOS shell.

Start by creating a **virtual environment**, a separate place to install this
project's Python packages. Activate it and install the package versions listed
in `requirements.txt`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Run the supplied tests:

```bash
python3 -m unittest -v test_secure_chat_starter.py
```

To focus on one test while debugging, give its module, class, and method name:

```bash
python3 -m unittest -v \
  test_secure_chat_starter.TestSecureChatStarter.test_authenticated_session_and_message
```

You may write additional local tests, including **regression tests** that
check that a bug stays fixed. These tests are not submitted or run for marks.
A useful security test checks all three of the following:

- The invalid operation raises the precise exception required by the
  specification.
- The participant's stored information, or **state**, remains as specified
  after the rejection. Check all relevant keys and counters, not just the
  exception.
- A related legitimate operation still succeeds. This is a **control**: it
  checks that the program has not simply stopped accepting all messages.

Keep your tests deterministic: the same test should consistently pass or fail
for the same behavior. Keys, nonces, signatures, session IDs, and ciphertexts
normally change between runs because the cryptography uses randomness. Check
properties such as lengths, successful decryption, and agreement between
participants instead of comparing against one hard-coded random output.

## `cryptography` API quick reference

An **API** is the set of functions and methods a library provides. Use the
library for the cryptographic operations and your code to enforce the protocol
rules. These examples show how to call the library, not complete project
functions. The starter file supplies the imports.

The algorithm names identify the exact tools to use: P-384 ECDH for agreeing
on a secret, Ed25519 for signatures, HKDF-SHA256 for deriving keys, and AES-GCM
for authenticated encryption. You do not need to derive their mathematics to
complete this project.

```python
# Fresh P-384 ECDH pair
private_key = ec.generate_private_key(ec.SECP384R1())
public_key = private_key.public_key()

# ECDH (both endpoints obtain the same bytes)
shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

# One 32-byte HKDF output. Construct a new HKDF object per derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=session_context,
    info=purpose_label,
).derive(secret)

# Ed25519 signatures
signature = identity_private_key.sign(data)
identity_public_key.verify(signature, data)  # returns None or raises InvalidSignature

# AES-GCM: ciphertext includes the 16-byte authentication tag
ciphertext_and_tag = AESGCM(message_key).encrypt(nonce, plaintext_bytes, aad)
plaintext_bytes = AESGCM(message_key).decrypt(nonce, ciphertext_and_tag, aad)
```

[Serialization](https://developer.mozilla.org/en-US/docs/Glossary/Serialization)
means converting a value into a format that can be sent or stored;
**parsing** means reading that format back. The **wire format** is the
representation that the two participants exchange, even though our simulation
runs in one process. Keep these representations straight:

- Cryptographic APIs consume `bytes`.
- User plaintext enters and leaves the protocol as Python `str`. Convert it
  to bytes with UTF-8 for encryption and decode it back after decryption.
- JSON cannot directly carry arbitrary bytes, so binary wire fields are
  lowercase hexadecimal strings.
- Hexadecimal represents each byte with two characters; for example,
  `b"Hi".hex()` is `"4869"`. `bytes.hex()` encodes bytes for JSON and
  `bytes.fromhex()` reverses it. Hex encoding does not encrypt anything.
- `bytes.fromhex()` accepts whitespace, so call the supplied
  `_decode_lower_hex()` helper on untrusted fields; uppercase or whitespace is
  not a valid protocol encoding.
- Do not call `.encode()` on a value that is already bytes, and do not pass a
  hex string directly to a cryptographic operation.

## Protocol specification

Follow this section exactly when implementing the TODOs. Two programs can use
the same cryptographic algorithms and still fail to communicate if their field
names, byte encodings, key labels, or message order differ. Function docstrings
in the starter file supply the corresponding argument checks and size limits.

### 1. Identity keys and trust

Each `Party` owns a long-term
[Ed25519 identity key pair](https://cryptography.io/en/50.0.1/hazmat/primitives/asymmetric/ed25519/#signing-verification). The private key signs
handshakes; the public key verifies those signatures. These are separate from
the temporary ECDH keys that establish a shared secret.

Save the peer's trusted 32-byte identity public key and compare incoming
handshakes against it. Saving a trusted key this way is called **pinning**.
The initial check must happen through an authenticated out-of-band process:
a trusted way to confirm the key's owner, separate from the attacker-controlled
messages. In this simulation, use `get_identity_public_bytes()` on the intended
peer. The identity key inside a received handshake is **not** automatically
trusted: an attacker could send their own key and sign with it.

`Party(name, identity_private_key=None)` requires a non-empty string name of at
most 100 characters.  A supplied private key must be an
`ed25519.Ed25519PrivateKey`; invalid names raise `ValueError` and invalid key
types raise `TypeError`.

### 2. Signed ephemeral handshake

**Ephemeral** means temporary: these ECDH keys are created for one session.
A **nonce** is a value used to distinguish one cryptographic operation from
another. Here, the handshake nonce is fresh random data that helps make each
handshake different. It is public, not a password.

Before each session, each participant generates:

- a fresh P-384 ECDH key pair; and
- a fresh 16-byte random nonce.

The **payload** is the content being signed. Both participants must use one
agreed byte representation of it, called a **canonical encoding**. For this
project, the payload is JSON with these exact string fields:

```text
version        = "CSC364-SecureChat-v2"
name           = the participant's expected display name
identity_key   = hex-encoded raw Ed25519 public key
ephemeral_key  = hex-encoded PEM P-384 public key
nonce          = hex-encoded 16-byte random value
```

Sign the canonical payload bytes with the Ed25519 private key. The transmitted
JSON object contains the payload plus a lowercase-hex-encoded Ed25519
`signature`. All hexadecimal wire values must contain only `0`-`9`/`a`-`f`,
with no whitespace. Canonical JSON uses sorted keys and separators
`(",", ":")`; use the supplied `_canonical_json()` helper. PEM is the text
format used by the supplied ECDH public-key serializer; the `ephemeral_key`
field carries those PEM bytes encoded as hex.

The received wire bytes must equal that canonical encoding of the complete
signed object. Reject duplicate fields, alternate field order, whitespace,
and alternate escapes as `ProtocolError` rather than normalizing them.
Malformed PEM keys and unsupported public-key algorithms or curves also raise
`ProtocolError`.

Choose one participant as the **initiator** and the other as the **responder**.
These roles fix a common ordering and the names of the two message directions;
both participants can send messages. A **transcript** is the record of the two
signed handshakes. A **hash** gives that record a fixed-size digest, which is
included when deriving keys to tie them to this particular exchange.

`establish_session()` must:

1. validate the schema (required fields and types), sizes, version, role,
   and P-384 curve;
2. compare the embedded identity key with `trusted_peer_identity`;
3. compare the signed name with the independently supplied 1-100 character
   `expected_peer_name`;
4. verify the Ed25519 signature;
5. order the two canonical signed handshakes as initiator then responder;
6. hash that transcript and bind the hash into HKDF's salt and `info` fields;
7. derive different initiator-to-responder and responder-to-initiator chains;
8. derive a fresh session ID from the transcript;
9. reset counters and skipped-message state; and
10. discard the ephemeral ECDH private key after successful establishment.

Any validation failure must leave the previous active session and pending
handshake state unchanged.

#### Required transcript and key labels

The formulas below are pseudocode: `||` means byte concatenation (`+` for
Python `bytes`), `SHA256` returns digest bytes, and `HEX` converts bytes to
lowercase hex. Every HKDF call uses SHA-256 and produces 32 bytes through your
`hkdf_expand` helper. The `salt` input supplies context, and `info` labels the
purpose of the output. Neither needs to be secret. Use the exact labels below.

Both participants must build byte-for-byte identical KDF input. Let
`initiator_handshake` and `responder_handshake` be the canonical encodings of
the complete signed wire objects. A length prefix records how many bytes follow
so the boundary between messages is unambiguous. Encode it as a four-byte,
unsigned, big-endian integer (most significant byte first):

```text
length_prefix(value) = len(value).to_bytes(4, "big") || value

transcript =
    b"CSC364 authenticated handshake v2|" ||
    length_prefix(initiator_handshake) ||
    length_prefix(responder_handshake)

transcript_hash = SHA256(transcript)
```

Use the transcript hash as HKDF salt and include it in each session-level
`info` value:

```text
root_key = HKDF(
    secret=ECDH_output,
    salt=transcript_hash,
    info=b"CSC364-v2 root key|" || transcript_hash
)

initiator_to_responder = HKDF(
    secret=root_key,
    salt=transcript_hash,
    info=b"CSC364-v2 initiator-to-responder chain|" || transcript_hash
)

responder_to_initiator = HKDF(
    secret=root_key,
    salt=transcript_hash,
    info=b"CSC364-v2 responder-to-initiator chain|" || transcript_hash
)

session_id = HEX(SHA256(b"CSC364-v2 session id|" || transcript_hash))
```

The initiator stores the first directional key for sending and the second for
receiving.  The responder stores them in the opposite positions.  A common bug
is to order the transcript as `local || peer`; that makes Alice and Bob hash
opposite orders and derive unrelated keys.

Example setup:

```python
alice = Party("Alice")
bob = Party("Bob")

alice_handshake = alice.create_handshake()
bob_handshake = bob.create_handshake()

alice.establish_session(
    bob_handshake,
    trusted_peer_identity=bob.get_identity_public_bytes(),
    expected_peer_name="Bob",
    role="initiator",
)
bob.establish_session(
    alice_handshake,
    trusted_peer_identity=alice.get_identity_public_bytes(),
    expected_peer_name="Alice",
    role="responder",
)
```

### 3. Symmetric-key ratchet

The **chain key** is the stored secret from which upcoming message keys are
derived. For each message, produce two outputs: a replacement chain key to
store, and a one-time message key to use for encryption or decryption. Both
outputs come from the current chain key:

```text
(next_chain_key, one_time_message_key) = ratchet_key(current_chain_key)
```

Using different purpose labels is called **domain separation**: it keeps keys
for different jobs distinct even when they come from the same secret. Use
these exact labels with `salt=None`:

```text
next_chain_key = HKDF(
    current_chain_key,
    info=b"CSC364-v2 symmetric ratchet|next-chain-key"
)

one_time_message_key = HKDF(
    current_chain_key,
    info=b"CSC364-v2 symmetric ratchet|message-key"
)
```

The sender uses the one-time key for exactly one message, then discards it.
The receiver discards that message's key after successfully processing the
message; it may temporarily retain keys for delayed messages as described
below. Store `next_chain_key` for the next operation. Do not use the next chain
key itself as the AES key.

Sending and receiving use independent chains. This separation prevents the
same chain state from being used in both network directions. For an optional
illustration, see Signal's explanation of the
[symmetric-key ratchet](https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet).
Its full Double Ratchet protocol includes additional features that are not
part of this project.

### 4. Message encryption and headers

AES-GCM protects the message text and produces an **authentication tag**, a
value the receiver checks to detect tampering. The library appends the 16-byte
tag to the ciphertext; keep it there. AES-GCM uses a 32-byte key and a fresh
12-byte random nonce. This nonce is separate from the handshake nonce.
For background on why AES-GCM needs this value, see the `iv` explanation in
[MDN's AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams#instance_properties);
our Python implementation requirements are the ones given here.

Each message also carries a **header**, which describes where the message
belongs. The header is visible but protected against changes:

```json
{
  "version": "CSC364-SecureChat-v2",
  "session_id": "<64 lowercase hex characters>",
  "direction": "initiator-to-responder",
  "message_number": 0
}
```

Data checked for tampering but left unencrypted is called **additional
authenticated data (AAD)**. Pass the canonical encoded header as AES-GCM's
AAD. For example, changing the message number must not let an attacker pass
off the ciphertext as a different message. Changing the header, nonce,
ciphertext, or authentication tag must make decryption fail.

`Party.send()` returns a dictionary with exactly `nonce`, `ciphertext`, and
`header`. Reject missing or extra fields in either the message or its header.
The message number must be a non-negative integer; booleans are not valid
message numbers.

Reject uppercase, whitespace-containing, odd-length, or out-of-bound
nonce/ciphertext encodings as `ProtocolError` before invoking AES-GCM.  In
particular, checking only that a nonce string has 24 characters is insufficient
because `bytes.fromhex()` ignores whitespace.

Sender state advances only after encryption succeeds.  Receiver state advances
only after AES-GCM authentication succeeds.

### 5. Replay and out-of-order handling

Messages may arrive in a different order from the one in which they were sent.
For example, if message 1 arrives before message 0, the receiver needs to move
its chain forward to read message 1 while keeping message 0's key for later.
A **skipped key** is one of these saved one-time message keys.

Message numbers begin at zero. A receiver may derive and retain up to
`MAX_SKIP = 100` skipped one-time message keys so later messages can arrive first.
This bound covers all retained skipped keys, including those from earlier gaps.
Each retained key is consumed only after successful authentication.  Already
consumed messages are replays and must be rejected.

The bound prevents a malicious or faulty peer from forcing unbounded key
derivation or storage.

### 6. State invariants and atomic updates

**State** is the data a `Party` remembers between method calls: its keys,
counters, session ID, and saved keys for delayed messages. An **invariant** is
a rule that must remain true before and after every public method call. Use
these rules to organize your code and tests:

- `sending_key` and `receiving_key` are either both `None` or both 32-byte
  chain keys for the active session.
- `send_count` is the number assigned to the next outgoing message.
- `receive_count` is one greater than the highest chain position already
  derived on the receiving side; it is not necessarily the count of plaintexts
  delivered when messages arrive out of order.
- Every entry in `_skipped_message_keys` has a number less than
  `receive_count`, has not been successfully used, and contains a one-time
  message key rather than a chain key.
- No accepted message key is retained after use.
- Failed parsing, signature verification, or AES-GCM authentication does not
  change active session state.

An **atomic update** means applying the new state only after the whole operation
succeeds. Work out candidate values in local variables first, and assign them
to `self` only after all checks pass. If a check fails, leave the previous
values in place:

```text
1. VALIDATE input and current state
2. CALCULATE candidate keys/counters in local variables
3. AUTHENTICATE the signature or ciphertext
4. COMMIT candidate values to self only after success
```

High-level sending pseudocode:

```text
require active session
header = current version/session/direction/send_count
candidate_chain, message_key = ratchet_key(sending_key)
wire = AES_GCM_ENCRYPT(message_key, plaintext, AAD=canonical(header))
wire.header = header
sending_key = candidate_chain
send_count += 1
return wire
```

High-level receiving pseudocode:

```text
require active session
validate exact message/header schemas and routing fields

if number < receive_count:
    require an unconsumed skipped key for number
    plaintext = AUTHENTICATE_AND_DECRYPT(skipped_key, message, header)
    delete skipped key
    return plaintext

require total skipped-key count to remain <= MAX_SKIP
candidate_chain = receiving_key
candidate_skipped = empty map

for each chain position from receive_count through number:
    candidate_chain, candidate_message_key = ratchet_key(candidate_chain)
    retain candidate_message_key if this is a skipped position

plaintext = AUTHENTICATE_AND_DECRYPT(target_message_key, message, header)
receiving_key = candidate_chain
receive_count = number + 1
merge candidate_skipped
return plaintext
```

The location of the authentication call matters.  Updating the chain first and
then discovering an invalid tag would let any attacker permanently move the
receiver out of sync.

### 7. Error contract

Use the specified exception types so callers and tests can tell what went
wrong. An invalid format, a failed identity check, and a replay are different
problems even though all should be rejected.

- Invalid local API argument types or values raise `TypeError` or `ValueError`
  as documented by the relevant function.
- Malformed, non-canonical, oversized, wrong-version, wrong-session, or
  wrong-direction network input raises `ProtocolError`.
- Sending or receiving without an active session, establishing without a
  pending handshake, creating a second pending handshake, or exceeding the
  total skipped-key bound also raises `ProtocolError`.
- A well-formed handshake that fails pinned-identity, expected-name, or
  signature verification raises `AuthenticationError`.
- A consumed message number with no retained skipped key raises `ReplayError`.
- A well-formed AES-GCM value with a wrong key, nonce, ciphertext, tag, or AAD
  raises `cryptography.exceptions.InvalidTag`.

All receive-side parsing, authentication, and skip-window failures leave the
active session state unchanged.  A failed session establishment leaves both
the previous active session and the pending local handshake unchanged so the
caller may retry with the same pending handshake.

## Adversarial recipes

An **adversarial recipe** is a short description of a security experiment:
what an attacker changes, what you expect to happen, and what legitimate
operation should still work afterward. Your report is **data-only**. The
grader reads your descriptions and runs the selected experiments using staff
code; it does not run code you write in the report or import your Python tests.

The five experiments cover different ways a messaging system can fail. Keep
all five sections in the supplied `adversarial_recipes.md` template:

- **Identity and transcript substitution**
- **AAD binding**
- **Ciphertext rejection without committing state**
- **Replay after reordering**
- **Old-session rejection**

The checker also lists shorter versions of these headings that it accepts.

### What to write

Replace the template's `TODO` placeholders with your answers. Write one short
answer per prompt in the form `Label: short answer`; bold labels, as used in
the template, are fine.

- **Attack:** describe the allowed replacement or change, where requested.
- **Expected result:** predict the outcome. If you expect rejection, identify
  the exact exception; otherwise predict no exception. Use the checker to
  confirm which exception it reads from your answer.
- **State after rejection:** say which stored values stay unchanged or
  advance, where requested.
- **Control:** describe the legitimate operation that should still succeed.
- **Delivery order** and **Replay message:** give the message numbers for the
  replay experiment.
- **Explanation:** optionally explain why your experiment checks the
  property. This helps staff understand your reasoning during review, but has
  no separate marks.

You do not need to copy a fixed sentence or use the grader's internal names.
To see the available experiment choices and examples of accepted wording, run:

```bash
python3 validate_adversarial_recipes.py --choices
```

This catalogue includes stronger and weaker experiments, predictions, and
controls. An entry tells you what the checker can understand, not whether the
answer is correct. Its examples are not the only accepted wording.

The **parser**, the part of the checker that turns your text into experiment
choices, understands common shorthand, ordinary filler words, and supported
synonyms. Capitalization, whitespace, Markdown emphasis, and backticks are
flexible. For example, `2 → 0 → 1` and `2, 0, 1` describe the same delivery order.

Accepted shorthand includes `msg`/`msgs` for message(s), `ct` for ciphertext,
`recv`/`rcv`/`rx` for receiving, `ctr` for counter, `hs` for handshake, `eph`
for ephemeral, `orig` for original, `prev` for previous, `sess` for session,
`auth` for authentication, and `w/` or `w/o` for with or without. Short labels
such as **Result**, **State**, **Order**, and **Replay msg** also work. For
example, "the tag check should fail" in the AAD experiment is read as
`InvalidTag`, and "retry the orig msg" means retry the original message.

The checker can only interpret the experiment choices it supports. A bare
"reject" does not specify an exact failure. If you name an exception, the
checker keeps that prediction even if it is wrong. Contradictory predictions
need staff review. Keep extra reasoning under **Explanation** so it does not
obscure your answer.

Write answers and explanations as plain text. Code blocks, block quotations,
and HTML are not read as answers. A link or image causes the containing
experiment to be flagged for staff review.

### What each experiment must check

Each recipe is worth 4 points. The requirements below describe the evidence
your experiment must provide; you still need to choose the experiment and
predict its exact result.

| Recipe | Required evidence | Points |
|---|---|---:|
| Identity and transcript substitution | One published signed-handshake substitution; its exact exception; unchanged active-session and pending-handshake state; an honest retry followed by a message round trip. | 4 |
| AAD binding | One change to AAD only, keeping the key, nonce, and ciphertext fixed; its exact exception; successful decryption of the original ciphertext with the correct AAD. | 4 |
| Ciphertext rejection without committing state | One change to the ciphertext only of a valid out-of-order message; its exact exception; unchanged full receiving state; successful retry of the original message. | 4 |
| Replay after reordering | One published delivery order and replay target; its exact exception; unchanged full receiving state; acceptance of each message once, followed by a same-session message round trip. | 4 |
| Old-session rejection | Delivery of an undelivered message from the previous session after a fresh session is established; its exact exception; unchanged receiving state in the fresh session; a fresh-session message round trip. | 4 |

A **message round trip** here checks that the participants can exchange
messages in both directions. Each attack needs a related legitimate control:
rejecting everything is not enough to satisfy the security requirements.

The AAD and ciphertext experiments test different things. In **AAD binding**,
change only the AAD and keep the key, nonce, and ciphertext fixed. If you also
changed the ciphertext, a failure could be caused by that change alone and
would not show that the AAD is checked. In **Ciphertext rejection without
committing state**, change only the ciphertext. Check that rejection does not
use up a message key, change the counter, or alter the saved skipped-message
keys. "Without committing state" means a failed attempt must not save changes
to those values.

The replay and old-session experiments also test different things. For
**Replay after reordering**, choose a replay message number smaller than the
first number in the delivery order. The receiver will then have first
accepted that message using a saved skipped-message key. **Old-session
rejection** instead tests whether sessions stay separate: deliver an
**undelivered** old message only after establishing a fresh session.

### How the recipes are marked

Each recipe has four checks, worth one point each:

1. You specify the precise sequence of changes and deliveries for the attack.
2. You predict the exact rejection, including preservation of all required
   state where applicable.
3. You specify the required legitimate control.
4. Your experiment agrees with the staff reference implementation and
   distinguishes it from staff **mutants**: implementations with deliberate
   bugs corresponding to the published requirements.

The grader interprets your report as data and uses staff-controlled code to
run these checks. It never executes your submitted text, code blocks, links,
or commands, and never imports student-authored Python tests.

An answer can be understood correctly but still earn less credit. Examples
include predicting no exception, checking only part of the state, using a
weaker control, or choosing a change that does not constitute the required
attack. Preserving only the receive counter is different from preserving the
entire receiving state. Retrying the original message after its altered
version was rejected is different from sending a fresh message.

### Check your report before submitting

Preview how the grader will read your answers:

```bash
python3 validate_adversarial_recipes.py adversarial_recipes.md
```

The public checker and staff grader use the same parsing code. The checker
shows the answers it understood and identifies relevant source lines. It does
not assess correctness or reveal staff tests. Read the interpreted answers
and check that they match what you meant; a successful interpretation alone
does not mean full marks.

Repeating an answer in equivalent wording produces a notice and keeps the
same interpretation. A missing answer, conflicting field, or unsupported
phrase sends the affected experiment for staff review instead of
automatically giving it zero. Other experiments that can be clearly
interpreted are graded independently. Staff resolve flagged experiments
using your original report and the same rubric. Review does not supply
missing technical reasoning or guarantee credit.

Submit only `adversarial_recipes.md` to the separate recipe assessment. Do not
submit the checker, dependencies, executable tests, or a JSON file there.
