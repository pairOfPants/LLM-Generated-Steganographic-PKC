# This is the core file for each function
# -- Imports --
from __future__ import annotations
import hashlib
import math
from chip.constants import H5

# Top Table 
TOP_F_TABLE = {
    (16, 1): 16,  (16, 2): 17,  (16, 3): 25,  (16, 4): 29,
    (32, 1): 32,  (32, 2): 34,  (32, 3): 49,  (32, 4): 58,
    (48, 1): 51,  (48, 2): 73,  (48, 3): 87,  (48, 4): 179,
    (64, 1): 68,  (64, 2): 97,  (64, 3): 116, (64, 4): 239,
    (96, 1): 102, (96, 2): 146, (96, 3): 174, (96, 4): 358,
    (128, 1): 136,(128, 2): 194,(128, 3): 232,(128, 4): 477
}

# PRF (SHAKE128)
# Create SHAKE128 hash object 
def PRF():
    maraca = hashlib.shake_128()

# Update hash object 


# Embedder LLM function
# -- Parameters -- 
# LLM: name of specific LLM model
# TOPIC: Topic of story generated
# Story0: Possible previous story 
# T0: Starting value for temperature 
# k0: inital value for the top k0 tokens w/ top k0 Probs
# C: sequence = [C0, C1,..., C_(n-1)] of chars from some sets S1,...,S4
# b: sequence of int = [b0,b1,...,b_(n-1)] {same number n as C}
import chip.constants as constants
from secrets import token_bytes
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, shake_128
from typing import List, Protocol
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EmbedderLLM(Protocol):
    def embed(
        self,
        topic: str,
        initial_story: str,
        characters: List[str],
        positions: List[int],
        temperature: float,
        top_k: int,
        security_level: int,
    ) -> str:
        ...
        #Algorithm 1 goes HERE


class LLMAuthenticatedEncryption:
    def __init__(
        self,
        embedder: EmbedderLLM,
    ) -> None:
        self.embedder = embedder


    def encrypt_to_story(
        self,
        password: str,
        plaintext: bytes,   
        topic: str,
    ) -> str:
        """
        Implements Algorithm 2.
        Expects plaintext, topic passed as arguments, whereas paper algorithm collects it inside alg
        """
    
        dk1, dk2 = self._derive_keys(password) #Line 1 of algorithm 2
        nonce = token_bytes(constants.NONCE_SIZE) #Prerequisite for line 3 of algorithm 2
        ciphertext_with_tag = self._aead_encrypt(   #Line 3
            key=dk1,
            nonce=nonce,
            plaintext=plaintext,
            associated_data=constants.ASSOCIATED_DATA,
        )
        enc_hex = ciphertext_with_tag.hex().upper() #Line 4/5 - treat ciphertext || tag as hex string

        mapped_chars = compute_encoding(enc_hex) #Line 6: C <- h5(enc)

        positions = self._generate_positions( #Lines 7,8,9 of algorithm 2 handled in this function
            seed=dk2,
            count=len(mapped_chars),
        )

        story = self.embedder.embed( #Line 11, create story given all other params
            topic = topic,
            initial_story = "",
            characters = mapped_chars,
            positions = positions,
            temperature = constants.TEMPERATURE,
            top_k = constants.TOP_K,
            security_level = constants.SECURITY_LEVEL,
        )

        return story #Step 12, return story (and eventually send to Bob)
    

    def _derive_keys(self, password: str) -> tuple[bytes, bytes]:
        """
        PBKDF2(password, Salt, count, 64)

        Split into:
            dk1 = first 32 bytes
            dk2 = last 32 bytes
        """

        derived = pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode(),
            salt=constants.SALT,
            iterations=constants.PBKDF2_iterations,
            dklen=64,
        )

        dk1 = derived[:32]
        dk2 = derived[32:]

        return dk1, dk2
    
    ''' 
    # AEAD Encryption
    '''
    def _aead_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> bytes:
        """
        AES-256-GCM authenticated encryption.

        cryptography library returns:
            ciphertext || tag
        """
        aesgcm = AESGCM(key)

        return nonce + aesgcm.encrypt(
            nonce,
            plaintext,
            associated_data,
        )
    

    # --------------------------------------------------------
    # Position Generation
    # --------------------------------------------------------

    def _generate_positions(
        self,
        seed: bytes,
        count: int,
    ) -> List[int]:
        """
        Reproduces Algorithm 2 steps 7-9:
          Init(SHAKE128(dk2))
          b0 = d0 + SHAKE128(chunk_size)
          bi = b_{i-1} + d0 + SHAKE128(chunk_size)

        Python's hashlib SHAKE128 does not support streaming reads, so we
        pre-generate all required XOF output in one call and then slice it
        into chunk_size-bit windows.
        """
        positions: List[int] = []
        current = 0
        chunk_size = constants.CHUNK_SIZE

        # Init(SHAKE128(dk2)) — seed the XOF with dk2, then read enough bytes
        # to cover count extractions of chunk_size bits each.
        needed_bytes = math.ceil(count * chunk_size / 8) + 1
        xof_output = shake_128(seed).digest(needed_bytes)
        bit_pos = 0

        for _ in range(count):
            random_value = self._next_shake_chunk(xof_output, bit_pos, chunk_size)
            bit_pos += chunk_size
            current += constants.OFFSET_DISTANCE + random_value
            positions.append(current)

        return positions

    def _next_shake_chunk(self, buf: bytes, bit_pos: int, chunk_size: int) -> int:
        """
        Extract chunk_size bits from the XOF output buffer starting at bit
        offset bit_pos.  Reads across byte boundaries safely.
        """
        byte_idx = bit_pos // 8
        bit_shift = bit_pos % 8
        hi = buf[byte_idx]
        lo = buf[byte_idx + 1] if byte_idx + 1 < len(buf) else 0
        word = (hi << 8) | lo
        return (word >> (16 - chunk_size - bit_shift)) & ((1 << chunk_size) - 1)

class LLMAuthenticatedDecryption:
    def __init__(
        self,
        password: str,
        story: str,
    ) -> None:
        self.password = password
        self.story = story

    def decrypt_from_story(self) -> bytes | None:
        """
        Implements Algorithm 3: LLM Authenticated Decryption and Verification.
        Returns plaintext bytes, or None if authentication fails.
        """
        # Line 1: derive the same two keys Alice used
        dk1, dk2 = self._derive_keys(self.password)

        # Lines 2-8: re-derive positions from dk2 and extract Story[pos] for each
        enc_chars = self._extract_chars(dk2)

        # Lines 9-12: invert h5 to recover the hex string
        # Build inverse lookup: H5 character → original hex character
        inverse_h5 = {}
        for hex_char in "0123456789ABCDEF":
            h5_char = compute_encoding(hex_char)[0]
            inverse_h5[h5_char] = hex_char

        try:
            hex_str = ''.join(inverse_h5[c] for c in enc_chars)
        except KeyError:
            return None  # Story contains an unexpected character

        # The encrypted blob produced by _aead_encrypt is: nonce (12 B) || ciphertext || tag (16 B)
        # In hex: 24 chars nonce + 2n chars ciphertext + 32 chars tag
        if len(hex_str) < 24 + 32:
            return None  # Too short to be a valid ciphertext

        nonce = bytes.fromhex(hex_str[:24])
        # AESGCM.decrypt expects ciphertext || tag as a single buffer
        ciphertext_with_tag = bytes.fromhex(hex_str[24:])

        # Line 13: AEAD_dec(dk1, nonce, AD, ciphertext || tag)
        return self._aead_decrypt(dk1, nonce, ciphertext_with_tag, constants.ASSOCIATED_DATA)

    def _derive_keys(self, password: str) -> tuple[bytes, bytes]:
        """PBKDF2(password, Salt, count, 64) → (dk1, dk2)."""
        derived = pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode(),
            salt=constants.SALT,
            iterations=constants.PBKDF2_iterations,
            dklen=64,
        )
        return derived[:32], derived[32:]

    def _extract_chars(self, dk2: bytes) -> List[str]:
        """
        Algorithm 3 lines 3-8.
        Re-derives the same position sequence Alice used and reads Story[pos]
        at each position while pos < len(Story).
        """
        story = self.story
        story_len = len(story)
        chunk_size = constants.CHUNK_SIZE

        # Upper bound on number of positions: story_len // OFFSET_DISTANCE
        max_positions = story_len // constants.OFFSET_DISTANCE + 1
        needed_bytes = math.ceil(max_positions * chunk_size / 8) + 1
        xof_output = shake_128(dk2).digest(needed_bytes)

        chars: List[str] = []
        bit_pos = 0

        # Line 4: first position = d_o + SHAKE128(chunk_size)
        random_value = self._next_shake_chunk(xof_output, bit_pos, chunk_size)
        bit_pos += chunk_size
        pos = constants.OFFSET_DISTANCE + random_value

        # Lines 5-8: while pos < len(Story), collect and advance
        while pos < story_len:
            chars.append(story[pos])
            random_value = self._next_shake_chunk(xof_output, bit_pos, chunk_size)
            bit_pos += chunk_size
            pos += constants.OFFSET_DISTANCE + random_value

        return chars

    def _next_shake_chunk(self, buf: bytes, bit_pos: int, chunk_size: int) -> int:
        """Extract chunk_size bits from buf starting at bit offset bit_pos."""
        byte_idx = bit_pos // 8
        bit_shift = bit_pos % 8
        hi = buf[byte_idx]
        lo = buf[byte_idx + 1] if byte_idx + 1 < len(buf) else 0
        word = (hi << 8) | lo
        return (word >> (16 - chunk_size - bit_shift)) & ((1 << chunk_size) - 1)

    def _aead_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes,
    ) -> bytes | None:
        """AES-256-GCM authenticated decryption. Returns None on auth failure."""
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception:
            return None
'''
compute_encoding(encoding):
computes the mapping of H_5 to the encoded input
inparams: encoding - the plaintext after being passed through the AEAD function
outparams: h5_embedding - the list of characters from H_5 that correspond to the encoded input
'''
def compute_encoding(encoding):
    #ensure all characters are uppercase letters
    encoding = encoding.upper()
    #Convert each character to hex
    hex_string = encoding.encode('utf-8').hex()
    #Normalize each character by subtracting 0x41 (uppercase A)
    normalized_pt = [int(hex_string[i:i+2], 16) - 0x41 for i in range(0, len(hex_string), 2)]
    #map normalized characters to H5
    h_mapped_chars = [H5[char][0] for char in normalized_pt]
    
    h5_embedding = [''] * len(h_mapped_chars)  # Initialize an empty list for the H5 embedding
    for i in range(len(h_mapped_chars)):
        h5_embedding[i] = H5[h_mapped_chars[i]][1]  # Get the character from H5 using the index

    return h5_embedding