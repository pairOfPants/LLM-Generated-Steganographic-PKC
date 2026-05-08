"""
Base interface for cryptographic procedures.
Concrete implementations will subclass CryptoEngine.
"""

from abc import ABC, abstractmethod


class CryptoEngine(ABC):
    """Abstract base class for all cryptographic procedures."""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext and return ciphertext."""
        ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext and return plaintext."""
        ...

    def describe(self) -> str:
        """Return a human-readable description of the algorithm."""
        return self.__class__.__name__
