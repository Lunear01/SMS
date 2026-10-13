"""Student-visible baseline tests for CSC 364 Project 1.

You may add local tests while developing.  The graded adversarial-test artifact
is the data-only ``adversarial_recipes.json`` file described in ``README.md``;
student Python tests are not executed for marks.
"""

import copy
import unittest

from cryptography.exceptions import InvalidTag

import secure_chat_starter as chat


class TestSecureChatStarter(unittest.TestCase):
    def establish(self):
        alice = chat.Party("Alice")
        bob = chat.Party("Bob")
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
        return alice, bob

    def test_ecdh_shared_secret_matches(self):
        private_a, public_a = chat.generate_ecdh_key_pair()
        private_b, public_b = chat.generate_ecdh_key_pair()
        self.assertEqual(
            chat.derive_shared_secret(private_a, public_b),
            chat.derive_shared_secret(private_b, public_a),
        )

    def test_party_rejects_invalid_constructor_inputs(self):
        with self.assertRaises(ValueError):
            chat.Party("")
        with self.assertRaises(TypeError):
            chat.Party("Alice", identity_private_key=object())

    def test_ratchet_returns_separate_keys(self):
        initial = chat.hkdf_expand(b"student-visible ratchet test")
        next_chain, message_key = chat.ratchet_key(initial)
        self.assertEqual(len(next_chain), 32)
        self.assertEqual(len(message_key), 32)
        self.assertNotEqual(next_chain, message_key)

    def test_encrypt_decrypt_round_trip_with_aad(self):
        key = chat.hkdf_expand(b"student-visible encryption test")
        encrypted = chat.encrypt_message(key, "Test message", b"header")
        self.assertEqual(
            chat.decrypt_message(key, encrypted, b"header"),
            "Test message",
        )

    def test_noncanonical_hex_is_a_protocol_error(self):
        key = b"K" * 32
        with self.assertRaises(chat.ProtocolError):
            chat.decrypt_message(
                key,
                {"nonce": "00 " * 8, "ciphertext": "00" * 16},
            )

    def test_authenticated_session_and_message(self):
        alice, bob = self.establish()
        self.assertEqual(alice.sending_key, bob.receiving_key)
        self.assertEqual(bob.receive(alice.send("hello")), "hello")

    def test_tampering_does_not_advance_receiver(self):
        alice, bob = self.establish()
        encrypted = alice.send("authenticate me")
        tampered = copy.deepcopy(encrypted)
        raw = bytearray.fromhex(tampered["ciphertext"])
        raw[0] ^= 0x01
        tampered["ciphertext"] = raw.hex()
        original_key = bob.receiving_key

        with self.assertRaises(InvalidTag):
            bob.receive(tampered)
        self.assertEqual(bob.receiving_key, original_key)
        self.assertEqual(bob.receive(encrypted), "authenticate me")

    # Add any extra local regression tests that help you develop and debug.
    # Keep them deterministic and assert precise exception types and state.
    def test_handshake_rejects_unpinned_identity(self):
        alice, bob, mallory = chat.Party("Alice"), chat.Party("Bob"), chat.Party("Mallory")
        alice.create_handshake()
        mallory_handshake = mallory.create_handshake()
        with self.assertRaises(chat.AuthenticationError):
            alice.establish_session(
                mallory_handshake,
                trusted_peer_identity=bob.get_identity_public_bytes(),
                expected_peer_name="Bob",
                role="initiator",
            )
        self.assertIsNone(alice.session_id)
        self.assertIsNotNone(alice._pending_ecdh_private)


if __name__ == "__main__":
    unittest.main()
