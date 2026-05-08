"""
CHIP - Cryptographic Hybrid Intelligence Platform
Entry point: verifies connectivity to Ollama and prints a hello-world response.
"""

import os

from chip.ollama_client import OllamaClient

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")


# def main():
#     print("=== CHIP - Cryptographic Hybrid Intelligence Platform ===\n")

#     client = OllamaClient(base_url=OLLAMA_HOST, model="gemma4:31b")

#     print(f"Connecting to Ollama at {client.base_url} ...")
#     try:
#         models = client.list_models()
#         print(f"Available models: {models}\n")
#     except ConnectionError as e:
#         print(f"[ERROR] {e}")
#         return

#     print("Sending hello-world prompt ...\n")
#     response = client.generate(
#         "Say hello and introduce yourself in one short sentence."
#     )
#     print(f"Ollama says:\n  {response}\n")
#     print("Setup complete.")
import embedder
def main():
    plaintext = "Hey"
    encoding = embedder.compute_encoding(plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Encoded: {encoding}")

if __name__ == "__main__":
    main()
