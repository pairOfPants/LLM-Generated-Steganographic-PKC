'''
main.py
Authors: Raiyaan Tareen, Aidan Denham
Simple driver file for generating a story
Please note that NO parts of this file were generated with the help of Artificial Intelligence.
'''
import os
import sys
from typing import List

sys.stdout.reconfigure(line_buffering=True)

import time
import embedder as embedder_module
from embedder import LLMAuthenticatedEncryption
from openai import OpenAI
import chip.constants as constants

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("CHIP_MODEL", "gemma3:1b")


class OllamaEmbedder:
    """Concrete EmbedderLLM drives embedderLLM via the Ollama OpenAI-compat API."""

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
    print("=== CSMC 443 Final Project ===\n")
    print("By: Raiyaan Tareen, Aidan Denham")
    # Wire the global OpenAI client used by embedderLLM / top_k_token_retriever
    embedder_module.client = OpenAI(
        base_url=f"{OLLAMA_HOST}/v1",
        api_key="ollama",
    )

    enc = LLMAuthenticatedEncryption(embedder=OllamaEmbedder(MODEL))

    password = "test"
    plaintext = b"hi"
    topic = "List the ABC's in english alphabet."

    print(f"Password : {password}", flush=True)
    print(f"Plaintext: {plaintext.decode()}", flush=True)
    print(f"Topic    : {topic}", flush=True)
    print("\nGenerating steganographic story ...\n", flush=True)
    print(f"[TIMING] Job started at {time.strftime('%Y-%m-%dT%H:%M:%S')}", flush=True)

    story = enc.encrypt_to_story(
        password=password,
        plaintext=plaintext,
        topic=topic,
    )

    print("=== Generated Story ===\n", flush=True)
    print(story, flush=True)
    print("\n=== End of Story ===", flush=True)

    print("\n=== Correctness Verification ===\n", flush=True)
    from tests import verify_story_correctness
    verify_story_correctness(story, password, plaintext)


if __name__ == "__main__":
    main()
