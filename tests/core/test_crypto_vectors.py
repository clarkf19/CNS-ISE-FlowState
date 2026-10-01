"""Known-answer tests for the crypto facade against the published standards."""

import pytest

from flowstate.core import crypto

h = bytes.fromhex


class TestEd25519RFC8032:
    @pytest.mark.parametrize(
        "secret, public, message, signature",
        [
            (  # RFC 8032 section 7.1, TEST 1
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (  # TEST 2
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ],
    )
    def test_vectors(self, secret, public, message, signature):
        key = crypto.SigningKey(h(secret))
        assert key.public_key().public_bytes() == h(public)
        assert key.sign(h(message)) == h(signature)
        assert crypto.VerifyKey(h(public)).verify(h(signature), h(message))

    def test_rejects_modified_message_and_signature(self):
        key = crypto.SigningKey.generate()
        sig = key.sign(b"amount=1000")
        assert not key.public_key().verify(sig, b"amount=10000")
        bad = bytearray(sig)
        bad[0] ^= 1
        assert not key.public_key().verify(bytes(bad), b"amount=1000")
        assert not key.public_key().verify(sig[:-1], b"amount=1000")

    def test_rejects_wrong_key_sizes(self):
        with pytest.raises(crypto.CryptoError):
            crypto.SigningKey(b"short")
        with pytest.raises(crypto.CryptoError):
            crypto.VerifyKey(b"\x00" * 31)


class TestX25519RFC7748:
    ALICE_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ALICE_PUB = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    BOB_PRIV = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    BOB_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def test_vector(self):
        alice = crypto.EphemeralKeyPair.from_private_bytes(h(self.ALICE_PRIV))
        bob = crypto.EphemeralKeyPair.from_private_bytes(h(self.BOB_PRIV))
        assert alice.public_bytes() == h(self.ALICE_PUB)
        assert bob.public_bytes() == h(self.BOB_PUB)
        assert alice.exchange(h(self.BOB_PUB)) == h(self.SHARED)
        assert bob.exchange(h(self.ALICE_PUB)) == h(self.SHARED)

    def test_ephemeral_key_is_single_use(self):
        a, b = crypto.EphemeralKeyPair(), crypto.EphemeralKeyPair()
        a.exchange(b.public_bytes())
        with pytest.raises(crypto.CryptoError):
            a.exchange(b.public_bytes())

    def test_rejects_low_order_point(self):
        with pytest.raises(crypto.CryptoError):
            crypto.EphemeralKeyPair().exchange(bytes(32))


def test_hkdf_rfc5869_case1():
    okm = crypto.hkdf_sha256(
        h("0b" * 22), salt=h("000102030405060708090a0b0c"), info=h("f0f1f2f3f4f5f6f7f8f9"), length=42
    )
    assert okm == h(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


class TestAesGcmSP80038D:
    def test_case_13_empty_plaintext(self):
        key = crypto.AeadKey(bytes(32))
        assert key.seal(bytes(12), b"", b"") == h("530f8afbc74536b9a963b4f1c4cb738b")

    def test_case_14(self):
        key = crypto.AeadKey(bytes(32))
        out = key.seal(bytes(12), bytes(16), b"")
        assert out == h("cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919")
        assert key.open(bytes(12), out, b"") == bytes(16)

    @pytest.mark.parametrize("where", ["ciphertext", "tag", "aad", "nonce"])
    def test_any_modification_fails(self, where):
        key = crypto.AeadKey(crypto.random_bytes(32))
        nonce, aad = crypto.random_bytes(12), b"header"
        ct = bytearray(key.seal(nonce, b"amount=1000", aad))
        if where == "ciphertext":
            ct[0] ^= 1
        elif where == "tag":
            ct[-1] ^= 1
        elif where == "aad":
            aad = b"headex"
        else:
            nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
        with pytest.raises(crypto.AuthenticationFailed):
            key.open(nonce, bytes(ct), aad)

    def test_rejects_bad_nonce_length(self):
        with pytest.raises(crypto.CryptoError):
            crypto.AeadKey(bytes(32)).seal(bytes(8), b"x", b"")


def test_constant_time_eq():
    assert crypto.constant_time_eq(b"abc", b"abc")
    assert not crypto.constant_time_eq(b"abc", b"abd")
