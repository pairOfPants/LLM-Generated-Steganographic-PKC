"""
CHIP - Cryptographic Hybrid Intelligence Platform
Entry point: test embed — encrypts a short plaintext and prints the resulting story.
"""

import os
import sys
from typing import List

sys.stdout.reconfigure(line_buffering=True)

import embedder as embedder_module
from embedder import LLMAuthenticatedEncryption
from openai import OpenAI
import chip.constants as constants

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("CHIP_MODEL", "jarvis:latest")


class OllamaEmbedder:
    """Concrete EmbedderLLM — drives embedderLLM via the Ollama OpenAI-compat API."""

    def __init__(self, model: str):
        self.model = model

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
        return embedder_module.embedderLLM(
            LLM=self.model,
            TOPIC=topic,
            Story0=initial_story,
            T0=temperature,
            k0=top_k,
            C=characters,
            b=positions,
            l=1,
            sec=security_level,
        )


def main():
    print("=== CHIP - Cryptographic Hybrid Intelligence Platform ===\n")

    # Wire the global OpenAI client used by embedderLLM / top_k_token_retriever
    embedder_module.client = OpenAI(
        base_url=f"{OLLAMA_HOST}/v1",
        api_key="ollama",
    )

    enc = LLMAuthenticatedEncryption(embedder=OllamaEmbedder(MODEL))

    password = "testpassword123"
    plaintext = b"You have nice manners"
    topic = "tell me the best Iron Man Suit in Six Words or less"

    print(f"Password : {password}", flush=True)
    print(f"Plaintext: {plaintext.decode()}", flush=True)
    print(f"Topic    : {topic}", flush=True)
    print("\nGenerating steganographic story ...\n", flush=True)

    story = enc.encrypt_to_story(
        password=password,
        plaintext=plaintext,
        topic=topic,
    )

    print("=== Generated Story ===\n", flush=True)
    print(story, flush=True)
    print("\n=== End of Story ===", flush=True)


if __name__ == "__main__":
    main()
