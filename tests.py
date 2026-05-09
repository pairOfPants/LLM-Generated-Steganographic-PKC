"""
Algorithm 2 unit tests.
Run with: python tests.py
"""

from embedder import LLMAuthenticatedEncryption, compute_encoding
from hashlib import shake_128
import chip.constants as constants


# ---------------------------------------------------------------------------
# Mock embedder — stands in for the real LLM during tests
# ---------------------------------------------------------------------------

class MockEmbedder:
    """Records the arguments passed to embed() and returns a deterministic story."""

    def __init__(self):
        self.last_call = {}

    def embed(
        self,
        topic,
        initial_story,
        characters,
        positions,
        temperature,
        top_k,
        security_level,
    ) -> str:
        self.last_call = {
            "topic": topic,
            "characters": characters,
            "positions": positions,
        }
        # Weave characters into a fake story so the return value is a non-empty string.
        return " ".join(characters)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pass(name: str):
    print(f"  [PASS] {name}")

def _fail(name: str, detail: str):
    print(f"  [FAIL] {name}: {detail}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_derive_keys():
    """_derive_keys is deterministic and produces two 32-byte keys."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    dk1a, dk2a = enc._derive_keys("correct-horse-battery-staple")
    dk1b, dk2b = enc._derive_keys("correct-horse-battery-staple")

    assert dk1a == dk1b, "dk1 not deterministic"
    assert dk2a == dk2b, "dk2 not deterministic"
    assert len(dk1a) == 32, f"dk1 length {len(dk1a)} != 32"
    assert len(dk2a) == 32, f"dk2 length {len(dk2a)} != 32"
    assert dk1a != dk2a, "dk1 and dk2 must differ"

    dk1c, _ = enc._derive_keys("different-password")
    assert dk1a != dk1c, "different passwords must produce different keys"

    _pass("derive_keys: deterministic, 32-byte keys, different passwords differ")


def test_aead_encrypt_structure():
    """_aead_encrypt output = nonce || ciphertext || 16-byte GCM tag."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    key = bytes(32)          # 32 zero bytes — valid AES-256 key
    nonce = bytes(12)        # 12 zero bytes
    plaintext = b"hello world"

    out = enc._aead_encrypt(key, nonce, plaintext, b"")

    # nonce (12) prepended by _aead_encrypt, then ciphertext (len(plaintext)), then tag (16)
    expected_len = 12 + len(plaintext) + 16
    assert len(out) == expected_len, f"output length {len(out)} != {expected_len}"
    assert out[:12] == nonce, "first 12 bytes must be the nonce"

    _pass("aead_encrypt: output length and nonce prefix correct")


def test_aead_encrypt_different_nonces():
    """Different nonces must produce different ciphertexts."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    key = bytes(32)
    pt = b"same plaintext"
    out1 = enc._aead_encrypt(key, bytes(12), pt, b"")
    out2 = enc._aead_encrypt(key, b"\x01" + bytes(11), pt, b"")
    assert out1 != out2, "different nonces must yield different ciphertexts"
    _pass("aead_encrypt: different nonces produce different ciphertexts")


def test_next_shake_chunk_alignment():
    """_next_shake_chunk extracts correct bits from a known buffer."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())

    # buf = 0b10110001  0b11001010  ...
    buf = bytes([0b10110001, 0b11001010, 0b00000000])

    # First 5 bits of byte 0: 0b10110 = 22
    assert enc._next_shake_chunk(buf, 0, 5) == 0b10110, \
        f"got {enc._next_shake_chunk(buf, 0, 5)}, expected 22"

    # Next 5 bits (offset 5): last 3 bits of byte 0 + first 2 of byte 1
    # 0b001 | 0b11 = 0b00111 = 7
    assert enc._next_shake_chunk(buf, 5, 5) == 0b00111, \
        f"got {enc._next_shake_chunk(buf, 5, 5)}, expected 7"

    _pass("next_shake_chunk: bit extraction correct at aligned and unaligned offsets")


def test_generate_positions_count_and_monotonic():
    """_generate_positions returns exactly `count` strictly increasing positions."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    seed = shake_128(b"test-seed").digest(32)
    count = 20

    positions = enc._generate_positions(seed, count)

    assert len(positions) == count, f"expected {count} positions, got {len(positions)}"
    for i in range(1, len(positions)):
        assert positions[i] > positions[i - 1], \
            f"positions not strictly increasing at index {i}"
    _pass("generate_positions: correct count and strictly increasing")


def test_generate_positions_gap_bounds():
    """Each gap between consecutive positions is in [OFFSET_DISTANCE, OFFSET_DISTANCE + 2^CHUNK_SIZE - 1]."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    seed = shake_128(b"gap-test").digest(32)
    positions = enc._generate_positions(seed, 50)

    lo = constants.OFFSET_DISTANCE
    hi = constants.OFFSET_DISTANCE + (2 ** constants.CHUNK_SIZE) - 1

    prev = 0
    for i, pos in enumerate(positions):
        gap = pos - prev
        assert lo <= gap <= hi, \
            f"gap {gap} at index {i} outside [{lo}, {hi}]"
        prev = pos
    _pass(f"generate_positions: all gaps in [{lo}, {hi}]")


def test_generate_positions_deterministic():
    """Same seed must always yield identical position sequences."""
    enc = LLMAuthenticatedEncryption(MockEmbedder())
    seed = b"\xde\xad\xbe\xef" * 8
    p1 = enc._generate_positions(seed, 15)
    p2 = enc._generate_positions(seed, 15)
    assert p1 == p2, "position generation is not deterministic"
    _pass("generate_positions: deterministic for same seed")


def test_compute_encoding_known_input():
    """compute_encoding maps uppercase-only hex chars to H5 characters."""
    # Use only A-F (valid uppercase hex chars whose ASCII codes fall in A-Z range).
    result = compute_encoding("ABCDEF")
    assert isinstance(result, list), "result should be a list"
    assert all(isinstance(c, str) and len(c) == 1 for c in result), \
        "each element should be a single character"
    # 'A' → ASCII 0x41, 0x41-0x41=0 → H5[0]=(0,' ') → H5[0][0]=0 → H5[0][1]=' '
    assert result[0] == " ", f"first char should be ' ', got {repr(result[0])}"
    _pass("compute_encoding: maps known input to correct H5 characters")


def test_compute_encoding_output_length():
    """Output length equals input length."""
    inp = "ABCDEF"
    result = compute_encoding(inp)
    assert len(result) == len(inp), \
        f"expected length {len(inp)}, got {len(result)}"
    _pass("compute_encoding: output length matches input length")


def test_encrypt_to_story_integration():
    """Full encrypt_to_story path: mock embedder receives correctly structured arguments."""
    mock = MockEmbedder()
    enc = LLMAuthenticatedEncryption(mock)

    story = enc.encrypt_to_story(
        password="test-password-123",
        plaintext=b"Attack at dawn",
        topic="Medieval warfare",
    )

    assert isinstance(story, str) and len(story) > 0, "story must be a non-empty string"

    call = mock.last_call
    assert call["topic"] == "Medieval warfare", "topic not forwarded"

    chars = call["characters"]
    positions = call["positions"]
    assert len(chars) == len(positions), "characters and positions must have the same length"
    assert all(isinstance(c, str) for c in chars), "all characters must be strings"
    assert positions == sorted(positions), "positions must be non-decreasing"

    _pass("encrypt_to_story: integration test passed — embedder received correct arguments")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_tests():
    print("\n=== Running Algorithm 2 Unit Tests ===\n")
    tests = [
        test_derive_keys,
        test_aead_encrypt_structure,
        test_aead_encrypt_different_nonces,
        test_next_shake_chunk_alignment,
        test_generate_positions_count_and_monotonic,
        test_generate_positions_gap_bounds,
        test_generate_positions_deterministic,
        test_compute_encoding_known_input,
        test_compute_encoding_output_length,
        test_encrypt_to_story_integration,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            _fail(t.__name__, str(e))
            failed += 1
        except Exception as e:
            _fail(t.__name__, f"unexpected error: {e}")
            failed += 1

    print(f"\n{passed}/{passed + failed} tests passed.\n")


if __name__ == "__main__":
    run_tests()
