#!/usr/bin/env python3
"""Interpret a bounded Markdown report of five adversarial experiments.

The public preview shows what the parser understood, never whether an answer
is correct. Use --choices for the complete neutral vocabulary. The same parser
is used by the staff scorer; ambiguous sections are routed to staff review.
Legacy JSON helpers remain available for instructor regression fixtures only.
"""

import argparse
import json
import os
import re
import unicodedata
from pathlib import Path
import stat
import sys


SCHEMA_VERSION = 2
MAX_RECIPE_BYTES = 32 * 1024
CATEGORY_IDS = (
    "identity_transcript_substitution",
    "aad_binding",
    "ciphertext_reject_without_commit",
    "replay_after_reordering",
    "old_session_rejection",
)

IDENTITY_ATTACK_VARIANTS = (
    "self_signed_same_name",
    "replace_signed_ephemeral_key",
    "flip_signed_nonce_bit",
)
AAD_MUTATIONS = (
    "flip_first_bit",
    "append_byte",
    "replace_all_bytes",
)
CIPHERTEXT_MUTATIONS = (
    "flip_first_ciphertext_bit",
    "flip_last_ciphertext_bit",
)
DELIVERY_ORDERS = (
    (2, 0, 1),
    (2, 1, 0),
    (1, 0, 2),
)
OLD_SESSION_ATTACK_VARIANTS = (
    "undelivered_message_from_previous_session",
    "already_delivered_message_from_previous_session",
    "fresh_session_message",
)

RECIPE_KEYS = {
    "identity_transcript_substitution": frozenset(
        {
            "category_id",
            "attack_variant",
            "expected_exception",
            "state_after_rejection",
            "legitimate_control",
        }
    ),
    "aad_binding": frozenset(
        {
            "category_id",
            "aad_mutation",
            "expected_exception",
            "legitimate_control",
        }
    ),
    "ciphertext_reject_without_commit": frozenset(
        {
            "category_id",
            "ciphertext_mutation",
            "expected_exception",
            "state_after_rejection",
            "legitimate_control",
        }
    ),
    "replay_after_reordering": frozenset(
        {
            "category_id",
            "delivery_order",
            "replay_message_number",
            "expected_replay_exception",
            "state_after_rejection",
            "legitimate_control",
        }
    ),
    "old_session_rejection": frozenset(
        {
            "category_id",
            "attack_variant",
            "expected_old_session_exception",
            "state_after_rejection",
            "legitimate_control",
        }
    ),
}

ENUM_FIELDS = {
    "identity_transcript_substitution": {
        "attack_variant": IDENTITY_ATTACK_VARIANTS,
        "expected_exception": (
            "AuthenticationError",
            "ProtocolError",
            "no_exception",
        ),
        "state_after_rejection": (
            "active_and_pending_unchanged",
            "active_session_only_unchanged",
            "pending_handshake_consumed",
        ),
        "legitimate_control": (
            "retry_original_handshake_then_round_trip",
            "old_session_round_trip_only",
            "no_control",
        ),
    },
    "aad_binding": {
        "aad_mutation": AAD_MUTATIONS,
        "expected_exception": (
            "InvalidTag",
            "ProtocolError",
            "no_exception",
        ),
        "legitimate_control": (
            "original_ciphertext_with_correct_aad",
            "fresh_ciphertext_with_correct_aad",
            "no_control",
        ),
    },
    "ciphertext_reject_without_commit": {
        "ciphertext_mutation": CIPHERTEXT_MUTATIONS,
        "expected_exception": (
            "InvalidTag",
            "ProtocolError",
            "no_exception",
        ),
        "state_after_rejection": (
            "receiving_state_unchanged",
            "receive_count_only_unchanged",
            "receiving_state_advanced",
        ),
        "legitimate_control": (
            "original_message_retry",
            "fresh_message_only",
            "no_control",
        ),
    },
    "replay_after_reordering": {
        "expected_replay_exception": (
            "ReplayError",
            "ProtocolError",
            "no_exception",
        ),
        "state_after_rejection": (
            "receiving_state_unchanged",
            "receive_count_only_unchanged",
            "receiving_state_advanced",
        ),
        "legitimate_control": (
            "accept_each_once_then_same_session_round_trip",
            "same_session_round_trip_only",
            "no_control",
        ),
    },
    "old_session_rejection": {
        "attack_variant": OLD_SESSION_ATTACK_VARIANTS,
        "expected_old_session_exception": (
            "ProtocolError",
            "ReplayError",
            "InvalidTag",
            "no_exception",
        ),
        "state_after_rejection": (
            "receiving_state_unchanged",
            "receive_count_only_unchanged",
            "receiving_state_advanced",
        ),
        "legitimate_control": (
            "fresh_session_round_trip",
            "old_session_round_trip_only",
            "no_control",
        ),
    },
}


class RecipeFormatError(ValueError):
    """Raised when a recipe file cannot be safely read or decoded."""


def _object_without_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RecipeFormatError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_nonstandard_number(token):
    raise RecipeFormatError(f"non-standard JSON number is not allowed: {token}")


def _read_recipe_source(path):
    """Read bounded UTF-8 from one regular, non-symlink file."""

    path = Path(path)
    flags = os.O_RDONLY
    # Opening a FIFO read-only otherwise blocks before fstat can reject it.
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RecipeFormatError(f"cannot open recipe file: {exc}") from exc
    try:
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise RecipeFormatError("recipe path must name a regular file")
        if file_status.st_size > MAX_RECIPE_BYTES:
            raise RecipeFormatError(
                f"recipe file exceeds {MAX_RECIPE_BYTES} bytes"
            )
        chunks = []
        remaining = MAX_RECIPE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) > MAX_RECIPE_BYTES:
            raise RecipeFormatError(
                f"recipe file exceeds {MAX_RECIPE_BYTES} bytes"
            )
    except OSError as exc:
        raise RecipeFormatError(f"cannot read recipe file: {exc}") from exc
    finally:
        os.close(descriptor)

    try:
        return encoded.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RecipeFormatError("recipe file must be UTF-8") from exc


def load_recipe_file(path):
    """Read a legacy JSON fixture; this is not the student Markdown interface."""
    source = _read_recipe_source(path)
    try:
        return json.loads(
            source,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_number,
        )
    except RecipeFormatError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RecipeFormatError(f"invalid JSON: {exc}") from exc


def _exact_keys(value, expected, path, errors):
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return False
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            errors.append(f"{path} is missing keys: {missing}")
        if extra:
            errors.append(f"{path} has unexpected keys: {extra}")
        return False
    return True


def _validate_enum(value, choices, path, errors):
    if not isinstance(value, str) or value not in choices:
        errors.append(f"{path} must be one of {list(choices)}")


def validate_recipe_document(document):
    """Return schema violations; an empty list means structurally valid."""

    errors = []
    if not _exact_keys(
        document,
        frozenset({"schema_version", "recipes"}),
        "$",
        errors,
    ):
        return errors

    if type(document["schema_version"]) is not int:
        errors.append("$.schema_version must be the integer 2")
    elif document["schema_version"] != SCHEMA_VERSION:
        errors.append("$.schema_version must equal 2")

    recipes = document["recipes"]
    if not isinstance(recipes, list):
        errors.append("$.recipes must be an array")
        return errors
    if len(recipes) != len(CATEGORY_IDS):
        errors.append("$.recipes must contain exactly five entries")
        return errors

    indexed = {}
    for index, recipe in enumerate(recipes):
        path = f"$.recipes[{index}]"
        if not isinstance(recipe, dict):
            errors.append(f"{path} must be an object")
            continue
        category_id = recipe.get("category_id")
        if not isinstance(category_id, str) or category_id not in CATEGORY_IDS:
            errors.append(
                f"{path}.category_id must be one of {list(CATEGORY_IDS)}"
            )
            continue
        if category_id in indexed:
            errors.append(
                f"category_id {category_id!r} must appear exactly once"
            )
            continue
        indexed[category_id] = recipe

        if not _exact_keys(recipe, RECIPE_KEYS[category_id], path, errors):
            continue
        for field, choices in ENUM_FIELDS[category_id].items():
            _validate_enum(recipe[field], choices, f"{path}.{field}", errors)

        if category_id == "replay_after_reordering":
            order = recipe["delivery_order"]
            if (
                not isinstance(order, list)
                or any(type(number) is not int for number in order)
                or tuple(order) not in DELIVERY_ORDERS
            ):
                errors.append(
                    f"{path}.delivery_order must be one of "
                    f"{[list(order) for order in DELIVERY_ORDERS]}"
                )
            replay_number = recipe["replay_message_number"]
            if type(replay_number) is not int or replay_number not in (0, 1):
                errors.append(f"{path}.replay_message_number must be 0 or 1")

    missing_categories = sorted(set(CATEGORY_IDS) - set(indexed))
    if missing_categories:
        errors.append(
            "each required category_id must appear exactly once; "
            f"missing: {missing_categories}"
        )
    return errors


# These tables are public interpretation rules, not scoring rules. Every
# permitted value, including weaker controls and incorrect predictions, has a
# readable alias. Do not replace whole-answer matching with keyword matching.
SECTION_TITLES = {
    "identity_transcript_substitution": "Identity and transcript substitution",
    "aad_binding": "AAD binding",
    "ciphertext_reject_without_commit": "Ciphertext rejection without committing state",
    "replay_after_reordering": "Replay after reordering",
    "old_session_rejection": "Old-session rejection",
}
SECTION_ALIASES = {
    "identity_transcript_substitution": ("Identity / transcript substitution", "Identity substitution", "Identity", "Handshake", "Identity auth"),
    "ciphertext_reject_without_commit": ("Ciphertext rejection without commit", "Ciphertext reject without commit", "Ciphertext", "Ciphertext rejection", "CT rejection"),
    "aad_binding": ("AAD", "Associated data"),
    "replay_after_reordering": ("Replay", "Reordering"),
    "old_session_rejection": ("Old session", "Session separation"),
}
FIELD_LABELS = {
    "attack_variant": "Attack",
    "aad_mutation": "Attack",
    "ciphertext_mutation": "Attack",
    "expected_exception": "Expected result",
    "expected_replay_exception": "Expected result",
    "expected_old_session_exception": "Expected result",
    "state_after_rejection": "State after rejection",
    "legitimate_control": "Control",
    "delivery_order": "Delivery order",
    "replay_message_number": "Replay message",
}
VALUE_ALIASES = {
    "self_signed_same_name": (
        "Use a self-signed identity with the same name",
        "Substitute a self-signed identity with the same name",
        "Present a self-signed handshake using the peer name",
    ),
    "replace_signed_ephemeral_key": ("Replace the signed ephemeral key",),
    "flip_signed_nonce_bit": ("Flip a bit in the signed nonce",),
    "flip_first_bit": (
        "Flip the first AAD bit", "Flip the first bit of the associated data",
        "Flip the first bit of the AAD, keeping the key, nonce, and ciphertext unchanged",
        "Flip the first bit of the associated data, keeping the key, nonce, and ciphertext unchanged",
    ),
    "append_byte": ("Append a byte to the associated data", "Append a byte to the AAD"),
    "replace_all_bytes": ("Replace all associated-data bytes", "Replace all AAD bytes"),
    "flip_first_ciphertext_bit": ("Flip the first ciphertext bit", "Flip the first bit of the ciphertext"),
    "flip_last_ciphertext_bit": ("Flip the last ciphertext bit", "Flip the last bit of the ciphertext"),
    "undelivered_message_from_previous_session": ("Deliver an undelivered message from the previous session",),
    "already_delivered_message_from_previous_session": ("Deliver an already delivered message from the previous session",),
    "fresh_session_message": ("Deliver a message from the fresh session",),
    "AuthenticationError": ("Authentication error",),
    "ProtocolError": ("Protocol error",),
    "InvalidTag": ("Invalid tag",),
    "ReplayError": ("Replay error",),
    "no_exception": ("No exception", "Accept without an exception"),
    "active_and_pending_unchanged": (
        "Active and pending state unchanged",
        "The active session and pending handshake stay unchanged",
    ),
    "active_session_only_unchanged": ("Only the active session stays unchanged", "Active session only unchanged"),
    "pending_handshake_consumed": ("The pending handshake is consumed", "Pending handshake consumed"),
    "receiving_state_unchanged": (
        "Receiving state unchanged", "The entire receiving state stays unchanged",
        "The full receiving state is unchanged",
    ),
    "receive_count_only_unchanged": (
        "Only the receive counter stays unchanged", "The receive counter stays unchanged",
        "Receive counter unchanged", "Counter unchanged",
    ),
    "receiving_state_advanced": ("The receiving state advances", "Receiving state advanced"),
    "retry_original_handshake_then_round_trip": (
        "Retry the original handshake, then exchange messages",
        "Retry the original handshake, then do a round trip",
    ),
    "old_session_round_trip_only": ("Exchange messages only in the old session", "Old-session round trip only"),
    "no_control": ("No control", "None"),
    "original_ciphertext_with_correct_aad": (
        "Decrypt the original ciphertext with the correct AAD",
        "The same ciphertext decrypts successfully with the original associated data",
    ),
    "fresh_ciphertext_with_correct_aad": ("Decrypt fresh ciphertext with the correct AAD",),
    "original_message_retry": ("Retry the original message",),
    "fresh_message_only": ("Try only a fresh message", "Fresh message only"),
    "accept_each_once_then_same_session_round_trip": (
        "Accept each message once, then exchange messages in the same session",
        "Accept each message once, then do a same-session round trip",
    ),
    "same_session_round_trip_only": ("Only exchange messages in the same session", "Same-session round trip only"),
    "fresh_session_round_trip": ("Exchange messages in the fresh session", "Fresh-session round trip"),
}
EXCEPTION_PREFIXES = ("raises ", "raise ", "decryption raises ", "the receiver raises ", "reject with ")


def _normalize(text):
    # Normalize presentation, not meaning: negation and conjunctions survive.
    text = unicodedata.normalize("NFKC", text).casefold().strip()
    text = text.replace("_", " ").replace("–", "-").replace("—", "-")
    return " ".join(text.rstrip(".").split())


# Shorthand is expanded as whole tokens. We retain negation, conjunctions,
# qualifiers such as "only", and attack details such as "first" versus "last".
SHORTHAND = {
    "msg": "message", "msgs": "message", "messages": "message",
    "ct": "ciphertext", "recv": "receiving", "rcv": "receiving",
    "rx": "receiving", "ctr": "counter", "hs": "handshake",
    "eph": "ephemeral", "orig": "original", "prev": "previous",
    "sess": "session", "auth": "authentication", "err": "error", "proto": "protocol", "1st": "first",
    "2nd": "second", "bits": "bit", "bytes": "byte",
}
FIELD_ALIASES = {
    "attack_variant": ("Experiment", "Attack variant"),
    "aad_mutation": ("Experiment", "AAD mutation", "Mutation"),
    "ciphertext_mutation": ("Experiment", "Ciphertext mutation", "Mutation"),
    "expected_exception": ("Result", "Expected outcome", "Expected", "Exception"),
    "expected_replay_exception": ("Result", "Expected outcome", "Expected", "Exception"),
    "expected_old_session_exception": ("Result", "Expected outcome", "Expected", "Exception"),
    "state_after_rejection": ("State", "State afterwards", "State after failure"),
    "legitimate_control": ("Legitimate control", "Honest control"),
    "delivery_order": ("Delivery", "Order", "Message order"),
    "replay_message_number": ("Replay msg", "Replay target", "Replay number", "Replay"),
}


def _loose_text(text):
    """Normalize harmless phrasing without deleting meaningful words."""
    text = _normalize(text).replace("’", "'")
    text = re.sub(r"\bw/o\b", "without", text)
    text = re.sub(r"\bw/", "with ", text)
    for contraction, expanded in {
        "doesn't": "does not", "don't": "do not", "didn't": "did not",
        "isn't": "is not", "aren't": "are not", "won't": "will not",
        "hasn't": "has not", "haven't": "have not", "can't": "cannot",
    }.items():
        text = re.sub(r"\b" + re.escape(contraction) + r"\b", expanded, text)
    text = text.replace("->", " then ").replace("→", " then ")
    text = re.sub(r"[-,;:.!?()[\]{}#\"/]", " ", text)
    words = [SHORTHAND.get(word, word) for word in text.split()]
    # Articles and these modal auxiliaries do not change the selected outcome.
    words = [word for word in words if word not in {"a", "an", "the", "should", "will", "would", "must"}]
    text = " ".join(words)
    text = re.sub(r"^(?:(?:i|we) (?:expect (?:that )?|think (?:that )?|plan to |intend to |want to )?|please )", "", text)
    text = re.sub(r"\bassociated data\b", "aad", text)
    for spaced, compact in (("authentication error", "authenticationerror"), ("protocol error", "protocolerror"), ("replay error", "replayerror"), ("invalid tag", "invalidtag")):
        text = re.sub(r"\b" + spaced + r"\b", compact, text)
    return text.strip()


def _section_id(title):
    title = re.sub(r"^\s*(?:(?:recipe|experiment)\s+)?[1-5][.):\s-]+", "", title, flags=re.IGNORECASE)
    normalized = _loose_text(title)
    for category in CATEGORY_IDS:
        names = (category, SECTION_TITLES[category], *SECTION_ALIASES.get(category, ()))
        if any(_loose_text(name) == normalized for name in names):
            return category
    return None


def _field_id(category, label):
    value = _loose_text(label)
    if value in ("explanation", "reasoning", "notes"):
        return "explanation"
    for field in RECIPE_KEYS[category] - {"category_id"}:
        names = (field, FIELD_LABELS[field], *FIELD_ALIASES.get(field, ()))
        if value in {_loose_text(name) for name in names}:
            return field
    return None


def _natural_matches(category, field, value):
    """Whole-clause, category-aware grammars; never search for isolated keywords.

    A single answer can match several equivalent forms of one value, but two
    distinct interpretations must go to review. Unconsumed words also require
    review; this deliberately rejects extra negations or contradictory clauses.
    """
    matches = set()

    def accept(canonical, *patterns):
        if any(re.fullmatch(pattern, value) for pattern in patterns):
            matches.add(canonical)

    if field == "delivery_order":
        order = re.fullmatch(r"(?:(?:deliver|receive|order|delivery order) )?(?:message )?([0-2])(?: then| and then| followed by)? (?:message )?([0-2])(?: then| and then| followed by)? (?:message )?([0-2])", value)
        if order and tuple(map(int, order.groups())) in DELIVERY_ORDERS:
            matches.add(tuple(map(int, order.groups())))
        return matches
    if field == "replay_message_number":
        target = re.fullmatch(r"(?:(?:replay|redeliver|deliver|send|resend) )?(?:message )?([01])(?: again)?", value)
        if target:
            matches.add(int(target.group(1)))
        return matches
    if field.startswith("expected_"):
        subject = r"(?:(?:decryption|receiver|receiving|it|function|call|operation|replay|handshake) )?"
        verb = r"(?:(?:raise[sd]?|throw[sn]?|return[sd]?|reject[sd]? with|fail[sd]? with|result[sd]? in) )?"
        for canonical in ENUM_FIELDS[category][field]:
            if canonical != "no_exception":
                accept(canonical, subject + r"(?:to )?" + verb + _loose_text(canonical) + r"(?: exception)?")
        accept("no_exception", r"no (?:exception|error)(?: is raised)?", r"(?:accept|succeed|succeeds)(?: without (?:exception|error))?", subject + r"(?:raise[sd]? no (?:exception|error)|does not (?:raise|throw) (?:exception|error))", r"(?:message|decryption|handshake) (?:is accepted|succeeds)")
        if category in ("identity_transcript_substitution", "aad_binding", "ciphertext_reject_without_commit"):
            canonical = "AuthenticationError" if category == "identity_transcript_substitution" else "InvalidTag"
            accept(canonical, r"authentication (?:fail[sd]?|is rejected)")
            if canonical == "InvalidTag":
                accept(canonical, r"(?:tag|authentication tag) (?:check|verification) fails?", r"tag does not verify")
        if category == "replay_after_reordering":
            accept("ReplayError", r"reject (?:replayed|duplicate) message", r"(?:replayed|duplicate) message (?:is rejected|fails replay check)")
        if category == "old_session_rejection":
            accept("ProtocolError", r"reject (?:message from (?:previous|old) session|(?:previous|old) session message)", r"(?:message from (?:previous|old) session|(?:previous|old) session message) is rejected")
        return matches

    if field == "state_after_rejection":
        unchanged = r"(?:(?:is|are|stay[sd]?|remain[sd]?|keep[s]?) )?(?:unchanged|same|same as before|unmodified|intact)|(?:does|do|did) not change|(?:is|are) not (?:changed|modified)"
        advanced = r"(?:advance[sd]?|change[sd]?|(?:is|gets) (?:advanced|changed|updated))"

        def state(canonical, target, outcome):
            accept(canonical, target + r" (?:" + outcome + r")", r"(?:keep|leave) " + target + r" (?:unchanged|same|intact|as is)", r"no change to " + target, r"unchanged " + target)

        if category == "identity_transcript_substitution":
            accept("active_and_pending_unchanged", r"unchanged|no changes?|same as before|as is")
            active = r"active(?: session| state)?"
            pending = r"pending(?: handshake| state)?"
            state("active_and_pending_unchanged", r"(?:" + active + r" and " + pending + r"|" + pending + r" and " + active + r")(?: state)?", unchanged)
            state("active_session_only_unchanged", r"(?:only )?active(?: session| state)(?: only)?", unchanged)
            accept("pending_handshake_consumed", r"pending handshake (?:is |gets )?(?:consumed|cleared|discarded)", r"(?:consume|clear|discard) pending handshake")
        else:
            accept("receiving_state_unchanged", r"unchanged|no changes?|same as before|as is")
            receiving = r"(?:(?:full|whole|entire|complete) )?(?:(?:receiving|receive|receiver) )?state"
            counter = r"(?:only )?(?:(?:receiving|receive|receiver) )?(?:counter|count)(?: only)?"
            state("receiving_state_unchanged", receiving, unchanged)
            state("receiving_state_unchanged", r"(?:receiving )?key (?:counter|count) and skipped keys(?: all)?", unchanged)
            state("receive_count_only_unchanged", counter, unchanged)
            accept("receiving_state_advanced", receiving + r" " + advanced, r"(?:advance|update) " + receiving)
        return matches

    flip = r"(?:flip|toggle|invert|tamper with)"
    if field in ("aad_mutation", "ciphertext_mutation"):
        target = "aad" if field == "aad_mutation" else "ciphertext"
        suffix = r"(?: (?:keeping|with) key nonce and ciphertext (?:unchanged|fixed))?" if field == "aad_mutation" else ""
        for position, canonical in (("first", "flip_first_bit" if field == "aad_mutation" else "flip_first_ciphertext_bit"), ("last", "flip_last_ciphertext_bit")):
            if field == "aad_mutation" and position == "last":
                continue
            accept(canonical, flip + r" " + position + r" (?:bit (?:of|in) " + target + r"|" + target + r" bit)" + suffix, flip + r" " + target + r" " + position + r" bit" + suffix)
        if field == "aad_mutation":
            accept("append_byte", r"(?:append|add) (?:one )?byte to (?:end of )?aad", r"aad append byte")
            accept("replace_all_bytes", r"(?:replace|change|overwrite) all (?:aad byte|byte (?:of|in) aad)")
        return matches
    if field == "attack_variant" and category == "identity_transcript_substitution":
        accept("replace_signed_ephemeral_key", r"(?:swap|replace|substitute|change) signed ephemeral key")
        accept("flip_signed_nonce_bit", flip + r" (?:one )?bit (?:in|of) signed nonce", flip + r" signed nonce bit")
        accept("self_signed_same_name", r"(?:use|present|substitute|send) self signed (?:identity|handshake|certificate) (?:with|using) (?:same|peer) name")
        return matches
    if field == "attack_variant" and category == "old_session_rejection":
        deliver = r"(?:deliver|send|submit|replay) "
        session = r"(?:previous|old) session"
        accept("undelivered_message_from_previous_session", deliver + r"(?:(?:previously )?undelivered message from " + session + r"|message from " + session + r" (?:that )?(?:has not been delivered(?: yet)?|was never delivered))", r"(?:previous|old) session message (?:not yet delivered|undelivered)")
        accept("already_delivered_message_from_previous_session", deliver + r"(?:already delivered message from " + session + r"|message from " + session + r" (?:that )?(?:has already been delivered|was already delivered))", r"(?:previous|old) session message already delivered")
        accept("fresh_session_message", deliver + r"(?:message from (?:fresh|new|current) session|(?:fresh|new|current) session message)")
        return matches
    if field == "legitimate_control":
        accept("no_control", r"(?:none|no (?:legitimate )?control|without control|do not run (?:any )?control)")
        round_trip = r"(?:exchange message|send and receive message|(?:do |run |perform )?round trip)"
        connector = r"(?:then|and then|followed by|and)"
        if category == "identity_transcript_substitution":
            accept("retry_original_handshake_then_round_trip", r"(?:retry|repeat|resend) original handshake " + connector + " " + round_trip)
        if category == "aad_binding":
            for variant, canonical in (("original|same", "original_ciphertext_with_correct_aad"), ("fresh|new", "fresh_ciphertext_with_correct_aad")):
                accept(canonical, r"(?:decrypt|try decrypting) (?:" + variant + r") ciphertext with (?:correct|original) aad", r"(?:" + variant + r") ciphertext (?:decrypts|is decrypted)(?: successfully)? with (?:correct|original) aad", r"(?:" + variant + r") ciphertext with (?:correct|original) aad")
        if category == "ciphertext_reject_without_commit":
            accept("original_message_retry", r"(?:retry|redeliver|resend|send again|try again) (?:original|same|unmodified) message", r"(?:original|same|unmodified) message (?:retry|again)", r"(?:send|try|deliver) (?:original|same|unmodified) message again")
            accept("fresh_message_only", r"(?:only )?(?:try|send|deliver|accept) (?:only )?(?:fresh|new) message(?: only)?", r"(?:fresh|new) message only")
        if category == "replay_after_reordering":
            accept("accept_each_once_then_same_session_round_trip", r"(?:accept|deliver|receive) (?:(?:each|every) message (?:exactly )?once|message once each) " + connector + " " + round_trip + r" in same session", r"(?:accept|deliver|receive) (?:each|every) message (?:exactly )?once " + connector + r" (?:do |run )?same session round trip")
            accept("same_session_round_trip_only", r"(?:only )?" + round_trip + r" (?:only )?in same session(?: only)?", r"(?:only )?same session round trip(?: only)?")
        if category in ("identity_transcript_substitution", "old_session_rejection"):
            accept("old_session_round_trip_only", r"(?:only )?" + round_trip + r" (?:only )?in (?:old|previous) session(?: only)?", r"(?:only )?(?:old|previous) session round trip(?: only)?")
        if category == "old_session_rejection":
            accept("fresh_session_round_trip", round_trip + r" in (?:fresh|new) session", r"(?:fresh|new) session round trip")
    return matches


def _interpret_value(category, field, text):
    if field in ("delivery_order", "replay_message_number") and re.search(
        r"[+-]\s*\d|\.\d", _normalize(text)
    ):
        # Signs and decimal points are numeric data, not decoration. Removing
        # them must not turn e.g. "2.0, 1" into the three-message order 2, 0, 1.
        return None
    value = _loose_text(text)
    matches = _natural_matches(category, field, value)
    if field not in ("delivery_order", "replay_message_number"):
        for canonical in ENUM_FIELDS[category][field]:
            if value in {_loose_text(alias) for alias in (canonical, *VALUE_ALIASES[canonical])}:
                matches.add(canonical)
            # Preserve the original documented prefix forms too.
            if field.startswith("expected_"):
                if any(value == _loose_text(prefix + alias) for prefix in EXCEPTION_PREFIXES for alias in (canonical, *VALUE_ALIASES[canonical])):
                    matches.add(canonical)
        matches &= set(ENUM_FIELDS[category][field])
    if len(matches) != 1:
        return None
    result = matches.pop()
    return list(result) if field == "delivery_order" else result


def _inline_text(node):
    """Return inline text and whether it is free of links, images, and HTML."""
    chunks, plain = [], True
    for child, entering in node.walker():
        if not entering:
            continue
        if child.t in ("html_inline", "link", "image"):
            plain = False
        if child.t in ("text", "code"):
            chunks.append(child.literal)
        elif child.t in ("softbreak", "linebreak"):
            chunks.append("\n")
    return "".join(chunks), plain


def parse_submission_file(path):
    """Interpret five sections; unresolved sections never become guessed answers.

    RecipeFormatError covers unsafe/unreadable/oversized/non-UTF-8 files only.
    Markdown-parser dependency failures propagate as infrastructure errors.
    Content errors, including a non-.md filename, produce review diagnostics.
    """
    source = _read_recipe_source(path)
    from commonmark import Parser

    document = Parser().parse(source)
    entries = {
        category: {"status": "needs_review", "recipe": None, "diagnostics": []}
        for category in CATEGORY_IDS
    }
    diagnostics = []
    sections = {}
    current = None

    def problem(message, line, category=None):
        diagnostic = f"line {line}: {message}"
        (entries[category]["diagnostics"] if category else diagnostics).append(diagnostic)

    def paragraph(node):
        nonlocal current
        if current is None:
            return
        text, plain = _inline_text(node)
        line = node.sourcepos[0][0]
        if not plain:
            problem("links, images, and HTML do not supply answers; use plain text", line, current)
            return
        fields = sections[current]["fields"]
        for offset, part in enumerate(text.splitlines()):
            field_match = re.match(r"^\s*([\w /-]+?)\s*:\s*(.*)$", part)
            if field_match:
                label, value = field_match.groups()
                field = _field_id(current, label)
                if field is None:
                    problem(f"unrecognized field {label!r}; use the template labels", line + offset, current)
                    sections[current]["last_field"] = None
                else:
                    supplied = {"text": value, "line": line + offset}
                    fields.setdefault(field, []).append(supplied)
                    sections[current]["last_field"] = supplied
            elif part.strip():
                last_field = sections[current].get("last_field")
                if last_field:
                    last_field["text"] += " " + part.strip()
                else:
                    problem("unlabelled text; put commentary under Explanation", line + offset, current)

    def block(node):
        nonlocal current
        line = node.sourcepos[0][0]
        if node.t == "heading":
            title, plain = _inline_text(node)
            category = _section_id(title) if plain else None
            if category:
                current = category
                if category in sections:
                    problem("duplicate experiment section; keep one section", line, category)
                else:
                    sections[category] = {"fields": {}, "line": line, "last_field": None}
            elif current is not None:
                problem("unrecognized heading inside an experiment; use the template headings", line, current)
                current = None
            return
        if node.t == "paragraph":
            paragraph(node)
        elif node.t in ("list", "item"):
            child = node.first_child
            while child:
                block(child)
                child = child.nxt
        elif node.t in ("code_block", "block_quote", "html_block"):
            # Do not descend: an example, quotation, or HTML comment must never
            # supply a real heading or field. Missing real answers trigger review.
            problem("code blocks, quotations, and HTML are ignored as answers", line)
            if current is not None:
                sections[current]["last_field"] = None
        elif node.t != "thematic_break" and current is not None:
            problem("unsupported answer formatting; use labelled plain-text fields", line, current)

    child = document.first_child
    while child:
        block(child)
        child = child.nxt

    wrong_extension = Path(path).suffix.casefold() != ".md"
    if wrong_extension:
        diagnostics.append("line 1: student submissions must use a .md filename")
    for category in CATEGORY_IDS:
        entry = entries[category]
        section = sections.get(category)
        if section is None:
            problem(f"missing section: {SECTION_TITLES[category]}", 1, category)
            continue
        if wrong_extension:
            problem("use a .md filename", section["line"], category)
        recipe = {"category_id": category}
        for field in sorted(RECIPE_KEYS[category] - {"category_id"}):
            supplied_rows = section["fields"].get(field)
            if supplied_rows is None:
                problem(f"missing field: {FIELD_LABELS[field]}", section["line"], category)
                continue
            values = []
            for supplied in supplied_rows:
                value = _interpret_value(category, field, supplied["text"])
                if value is None:
                    problem(f"cannot interpret {FIELD_LABELS[field]}: {supplied['text']!r}; use --choices or staff review", supplied["line"], category)
                values.append(value)
            if any(value is None for value in values):
                continue
            if any(value != values[0] for value in values[1:]):
                problem(f"conflicting duplicate field: {FIELD_LABELS[field]}", supplied_rows[-1]["line"], category)
                continue
            recipe[field] = values[0]
            if len(values) > 1:
                problem(f"repeated {FIELD_LABELS[field]} has the same interpretation; accepted", supplied_rows[1]["line"])
        if not entry["diagnostics"]:
            entry.update(status="parsed", recipe=recipe)
    return {"recipes": entries, "diagnostics": diagnostics}


def print_choices():
    print("Accepted interpretations (this list does not identify correct answers).")
    print("Use ## headings and Label: answer fields. Case, punctuation, emphasis,")
    print("inline backticks, and whitespace are flexible. Optional Explanation is ungraded.")
    print("The aliases below are examples, not an exhaustive list of accepted sentences.")
    print("Whole-clause rules also accept I would/I expect, should/will, articles,")
    print("flip/toggle/invert, swap/replace, retry/resend, and supported word orders.")
    print("Shorthand: " + ", ".join(f"{short}={long}" for short, long in SHORTHAND.items()))
    print("Also w/=with; w/o=without. Negation and only/or/but are preserved.")
    print("Examples: retry the orig msg; recv state stays the same;")
    print("the recv ctr does not change (counter only); swap signed eph key;")
    print("flip 1st bit of ct; deliver msg #0 again; msgs 2 then 0 then 1.")
    print("Result clauses: auth fails means AuthenticationError in identity and InvalidTag")
    print("in AAD/ciphertext; tag check fails means InvalidTag; reject the replayed msg")
    print("means ReplayError in replay; reject msg from prev sess means ProtocolError")
    print("in old-session. An explicit allowed exception stays exactly that exception.")
    print("Bare reject, contradictory clauses, or wording with multiple meanings need review.")
    print("Equivalent repeated fields are accepted with a notice; conflicting repeats need review.")
    print("Canonical IDs/field names are accepted. Field label aliases are shown below.")
    print("Expected result may prefix a choice with: " + ", ".join(repr(p.strip()) for p in EXCEPTION_PREFIXES))
    for category in CATEGORY_IDS:
        print(f"\n## {SECTION_TITLES[category]} ({category})")
        if SECTION_ALIASES.get(category):
            print("Heading aliases: " + "; ".join(SECTION_ALIASES[category]))
        for field in sorted(RECIPE_KEYS[category] - {"category_id"}):
            print(f"{FIELD_LABELS[field]} ({field}; aliases: {'; '.join(FIELD_ALIASES.get(field, ()))}):")
            if field == "delivery_order":
                print("  2, 0, 1 | 2, 1, 0 | 1, 0, 2 (commas, →, or ->; optional brackets)")
            elif field == "replay_message_number":
                print("  0 | 1 | Message 0 | Message 1")
            else:
                for value in ENUM_FIELDS[category][field]:
                    print("  " + " | ".join((value, *VALUE_ALIASES[value])))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recipe_file", nargs="?", type=Path, default=Path("adversarial_recipes.md"))
    parser.add_argument("--choices", action="store_true", help="list choices, shorthand, and natural-language interpretation examples")
    args = parser.parse_args(argv)
    if args.choices:
        print_choices()
        return 0
    try:
        result = parse_submission_file(args.recipe_file)
    except RecipeFormatError as exc:
        print(f"NEEDS REVIEW: {exc}")
        return 1
    except ImportError:
        print("CHECKER UNAVAILABLE: install the pinned requirements.txt dependencies")
        return 2
    print("Interpretation preview only; this does not check correctness or award marks.")
    for diagnostic in result["diagnostics"]:
        print(f"- {diagnostic}")
    needs_review = False
    for category, entry in result["recipes"].items():
        print(f"\n{SECTION_TITLES[category]}: {entry['status']}")
        if entry["status"] == "parsed":
            for field, value in entry["recipe"].items():
                if field != "category_id":
                    print(f"  {FIELD_LABELS[field]}: {value}")
        else:
            needs_review = True
            for diagnostic in entry["diagnostics"]:
                print(f"  - {diagnostic}")
    return 1 if needs_review else 0


if __name__ == "__main__":
    sys.exit(main())
