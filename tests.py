"""
tests.py
Authors: Raiyaan Tareen, Aidan Denham
Unit tests for Algorithm 2 and Algorithm 3 components, using a MockEmbedder to isolate the cryptographic logic from LLM variability. 
Also includes a full encrypt-decrypt round-trip test and per-character validation
Please note that parts of this file were created with the help of Artificial Intelligence, especially the MockEmbedder class.
"""

from embedder import LLMAuthenticatedEncryption, LLMAuthenticatedDecryption, compute_encoding
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


def test_compute_encoding_no_negative_indices():
    """
    Regression test: compute_encoding must not produce negative H5 indices.

    compute_encoding("4A2F") exposes a double-encoding bug:
      The function calls .encode('utf-8').hex() on the input, treating '4'
      (ASCII 0x34) as a raw byte instead of treating '4' as the hex digit 4.
      This produces values below 0x41 after the subtraction step, giving
      negative indices. Python silently wraps these (H5[-13] == H5[3]),
      so no IndexError is raised — the wrong characters are produced silently.

    The correct behaviour for hex input "4A2F":
      '4' → index 4  → H5[4][1]  = 'O'
      'A' → index 0  → H5[0][1]  = ' '
      '2' → index 2  → H5[2][1]  = 'T'
      'F' → index 5  → H5[5][1]  = 'N'
    (i.e. each hex digit value maps directly to that H5 index)
    """
    from chip.constants import H5

    test_input = "4A2F"

    try:
        result = compute_encoding(test_input)
    except Exception as e:
        _fail("compute_encoding_no_negative_indices",
              f"raised unexpected exception: {e}")
        return

    # Hex digit values: '4'->4, 'A'->10, '2'->2, 'F'->15
    expected = [H5[4][1], H5[10][1], H5[2][1], H5[15][1]]

    assert result == expected, (
        f"compute_encoding('4A2F') returned {result!r}, expected {expected!r}. "
        "Digit characters like '4' (0x34) produce negative indices (0x34-0x41=-13) "
        "which Python wraps silently — H5[-13]==H5[3], giving wrong output."
    )

    _pass("compute_encoding: digit characters map to correct H5 indices (no negative-index wrap)")


def test_compute_encoding_known_input():
    """compute_encoding maps uppercase-only hex chars to H5 characters."""
    # Use only A-F (valid uppercase hex chars whose ASCII codes fall in A-Z range).
    result = compute_encoding("ABCDEF")
    assert isinstance(result, list), "result should be a list"
    assert all(isinstance(c, str) and len(c) == 1 for c in result), \
        "each element should be a single character"
    # compute_encoding uses int(ch, 16) to index into H4, not ASCII subtraction.
    # 'A' → int('A', 16) = 10 → H4[10] = (10, 'D')
    expected_first = constants.H4[10][1]  # 'D'
    assert result[0] == expected_first, \
        f"first char should be '{expected_first}', got {repr(result[0])}"
    _pass("compute_encoding: maps known input to correct H4 characters")


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


def test_encrypt_decrypt_roundtrip():
    """Full Algorithm 2 → Algorithm 3 round-trip with a fixed plaintext."""
    PASSWORD = "test-password"
    PLAINTEXT = b"Hello world!"

    class PositionEmbedder:
        """
        Minimal embedder that places each character at its exact required
        position in the story, padding everything else with 'X'.
        The story ends immediately after the last character position so that
        the decryption loop stops at exactly the right point.
        """
        def embed(
            self, topic, initial_story, characters, positions,
            temperature, top_k, security_level,
        ) -> str:
            story = ['X'] * (positions[-1] + 1)
            for char, pos in zip(characters, positions):
                story[pos] = char
            return ''.join(story)

    print(f"  [LOG] plaintext:       {PLAINTEXT!r}")

    # --- Encryption ---
    enc = LLMAuthenticatedEncryption(PositionEmbedder())
    story = enc.encrypt_to_story(
        password=PASSWORD,
        plaintext=PLAINTEXT,
        topic="Test",
    )
    assert isinstance(story, str) and len(story) > 0, "story must be non-empty"
    print(f"  [LOG] encrypted story: {story!r}")
    _pass("roundtrip: encryption produced a non-empty story")

    # --- Decryption with correct password ---
    dec = LLMAuthenticatedDecryption(password=PASSWORD, story=story)
    recovered = dec.decrypt_from_story()
    assert recovered is not None, "decryption returned None (authentication failure)"
    assert recovered == PLAINTEXT, f"decrypted {recovered!r} != expected {PLAINTEXT!r}"
    print(f"  [LOG] decrypted:       {recovered!r}")
    _pass("roundtrip: correct password recovers original plaintext")

    # --- Wrong password must be rejected ---
    dec_bad = LLMAuthenticatedDecryption(password="wrong-password", story=story)
    bad_result = dec_bad.decrypt_from_story()
    print(f"  [LOG] wrong password result: {bad_result!r}")
    assert bad_result is None, \
        "wrong password should cause auth failure (None), but it succeeded"
    _pass("roundtrip: wrong password correctly rejected")


# ---------------------------------------------------------------------------
# Character-placement verification helper
# ---------------------------------------------------------------------------

def verify_character_placement(story: str, characters: list, positions: list) -> list:
    """
    Given a completed story and the (characters, positions) sequence that was
    supposed to be embedded, return a list of failure dicts for every position
    where story[pos].upper() != char.upper().

    Each failure dict has keys: index, pos, expected, actual.

    An empty return list means every character is at the correct position.
    This helper is useful both in unit tests (with a mock embedder) and
    for post-hoc verification of a real LLM-generated story.
    """
    failures = []
    for idx, (char, pos) in enumerate(zip(characters, positions)):
        if pos >= len(story):
            failures.append({
                "index": idx, "pos": pos, "expected": char,
                "actual": "<story too short>",
            })
        elif story[pos].upper() != char.upper():
            failures.append({
                "index": idx, "pos": pos, "expected": char,
                "actual": story[pos],
            })
    return failures


def verify_story_correctness(story: str, password: str, plaintext: bytes) -> bool:
    """
    Verify that `story` correctly embeds `plaintext` under `password`.

    Re-derives the position sequence and expected characters from first principles,
    compares every story[pos] against the expected H4 character, then runs AEAD
    decryption as the ground-truth check.

    Designed to be called against a real LLM-generated story from any hardware:

        from tests import verify_story_correctness
        verify_story_correctness(story, password, plaintext)

    Returns True if every character placement and AEAD decryption are correct.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def _display(b: bytes) -> str:
        try:
            return repr(b.decode())
        except UnicodeDecodeError:
            return repr(b)

    enc_helper = LLMAuthenticatedEncryption(None)
    dk1, dk2 = enc_helper._derive_keys(password)

    # Total embedded hex chars = 2 * (nonce || plaintext || 16-byte GCM tag)
    n = 2 * (constants.NONCE_SIZE + len(plaintext) + 16)
    positions = enc_helper._generate_positions(dk2, n)

    # H4 inverse: character → hex digit string
    inverse_h4 = {char: format(idx, 'X') for idx, (_, char) in enumerate(constants.H4)}

    # ── 1. Extract characters from the story at every expected position ────────
    extracted = []
    too_short = []
    for i, pos in enumerate(positions):
        if pos >= len(story):
            extracted.append(None)
            too_short.append(i)
        else:
            extracted.append(story[pos].upper())

    bad_alphabet = [i for i, c in enumerate(extracted)
                    if c is not None and c not in inverse_h4]

    # ── 2. Recover the nonce from the embedded positions, then re-encrypt ──────
    valid_chars = [c for c in extracted if c is not None]
    hex_str = ''.join(inverse_h4.get(c, '0') for c in valid_chars)
    nonce_hex_len = constants.NONCE_SIZE * 2

    all_ok = True
    if len(hex_str) >= nonce_hex_len:
        nonce = bytes.fromhex(hex_str[:nonce_hex_len])

        # Re-encrypt with the recovered nonce — GCM is deterministic given (key, nonce, pt, aad)
        aesgcm = AESGCM(dk1)
        expected_blob = nonce + aesgcm.encrypt(nonce, plaintext, constants.ASSOCIATED_DATA)
        expected_hex = expected_blob.hex().upper()
        expected_chars = [constants.H4[int(ch, 16)][1] for ch in expected_hex]

        # ── 3. Per-character comparison ───────────────────────────────────────
        mismatches = []
        for i, (exp, pos) in enumerate(zip(expected_chars, positions)):
            actual = extracted[i] if i < len(extracted) else None
            if actual is None:
                mismatches.append((i, pos, exp, '<story too short>'))
            elif actual != exp.upper():
                mismatches.append((i, pos, exp, actual))

        if mismatches:
            all_ok = False
            total = len(expected_chars)
            print(f"  Placement: {len(mismatches)}/{total} characters wrong")
            for m in mismatches[:10]:
                print(f"    char {m[0]:4d}  pos {m[1]:6d}  expected '{m[2]}'  found '{m[3]}'")
            if len(mismatches) > 10:
                print(f"    ... and {len(mismatches) - 10} more")
    else:
        all_ok = False
        print("  Could not recover nonce — too few characters extracted from story.")

    if too_short:
        print(f"  Story too short: {len(too_short)} positions beyond end "
              f"(story_len={len(story)}, last required pos={positions[-1]})")
    if bad_alphabet:
        print(f"  {len(bad_alphabet)} extracted characters not in H4 alphabet")

    # ── 4. AEAD decryption as ground-truth ────────────────────────────────────
    dec = LLMAuthenticatedDecryption(password=password, story=story)
    recovered = dec.decrypt_from_story()

    print(f"  Plaintext  : {_display(plaintext)}")
    print(f"  Ciphertext : {hex_str}  ({len(hex_str)} hex chars embedded across {len(story)}-char story)")
    if recovered == plaintext:
        print(f"  Decrypted  : {_display(recovered)}")
    else:
        all_ok = False
        if recovered is None:
            print(f"  Decrypted  : FAIL (authentication error — wrong password or tampered story)")
        else:
            print(f"  Decrypted  : FAIL (got {_display(recovered)}, expected {_display(plaintext)})")

    return all_ok


# ---------------------------------------------------------------------------
# Parameterised placement + decryption test
# ---------------------------------------------------------------------------

def test_character_placement_and_decrypt_arbitrary_sizes():
    """
    For plaintexts of various sizes, verifies two things end-to-end:

      1. Character placement — every mapped_chars[i] appears at positions[i]
         in the generated story (caught by inspecting the story the embedder
         returned, using the characters/positions it was given).

      2. Decryption correctness — decrypt_from_story() with the correct
         password recovers the exact original plaintext bytes.

      3. Wrong-password rejection — decrypt_from_story() with a different
         password returns None.

    A PositionEmbedder is used so the story is constructed deterministically:
    it places each required character at exactly the required index, padding
    all other positions with 'x'.  This isolates the cryptographic and
    position-generation logic from LLM variability.
    """

    class RecordingPositionEmbedder:
        """Places each char at its exact required position and records the call."""
        def __init__(self):
            self.characters = None
            self.positions = None

        def embed(self, topic, initial_story, characters, positions,
                  temperature, top_k, security_level) -> str:
            self.characters = list(characters)
            self.positions = list(positions)
            story = ['x'] * (positions[-1] + 1)
            for char, pos in zip(characters, positions):
                story[pos] = char
            return ''.join(story)

    test_cases = [
        ("tiny",   b"A"),
        ("small",  b"Hello!"),
        ("medium", b"Attack at dawn, general."),
        ("large",  b"The quick brown fox jumps over the lazy dog. " * 4),
        ("bytes",  bytes(range(32))),   # arbitrary binary content
    ]

    all_passed = True
    for label, plaintext in test_cases:
        password = f"test-password-{label}"
        embedder = RecordingPositionEmbedder()
        enc = LLMAuthenticatedEncryption(embedder)

        story = enc.encrypt_to_story(
            password=password,
            plaintext=plaintext,
            topic="Test topic",
        )

        print(
            f"    [LOG] label={label:<8s} plaintext_len={len(plaintext):4d} "
            f"n={len(embedder.positions):4d} story_len={len(story):6d}",
            flush=True,
        )

        ok = verify_story_correctness(story, password, plaintext)
        if ok:
            _pass(f"character_placement_and_decrypt: {label} (plaintext_len={len(plaintext)})")
        else:
            _fail(f"character_placement_and_decrypt [{label}]",
                  "see [VERIFY] lines above")
            all_passed = False

    if not all_passed:
        raise AssertionError("One or more size variants failed — see above.")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_tests():
    print("\n=== Running Algorithm 2 & 3 Unit Tests ===\n")
    tests = [
        test_derive_keys,
        test_aead_encrypt_structure,
        test_aead_encrypt_different_nonces,
        test_next_shake_chunk_alignment,
        test_generate_positions_count_and_monotonic,
        test_generate_positions_gap_bounds,
        test_generate_positions_deterministic,
        test_compute_encoding_no_negative_indices,
        test_compute_encoding_known_input,
        test_compute_encoding_output_length,
        test_encrypt_to_story_integration,
        test_encrypt_decrypt_roundtrip,
        test_character_placement_and_decrypt_arbitrary_sizes,
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
