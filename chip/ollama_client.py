"""
Ollama API client for interacting with a local Ollama instance.
Default endpoint: http://localhost:11434
"""

import json
import urllib.request
import urllib.error
from typing import Iterator

OLLAMA_BASE_URL = "http://localhost:11434"


class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model: str = "llama3"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def _post(self, endpoint: str, payload: dict) -> dict:
        url = f"{self.base_url}{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Could not reach Ollama at {self.base_url}. "
                "Ensure Ollama is running on port 11434."
            ) from e

    def generate(self, prompt: str, stream: bool = False) -> str:
        """Send a generation prompt and return the response text."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
        }
        result = self._post("/api/generate", payload)
        return result.get("response", "")

    def chat(self, messages: list[dict], stream: bool = False) -> str:
        """Send a chat message list and return the assistant's reply."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
        }
        result = self._post("/api/chat", payload)
        return result.get("message", {}).get("content", "")

    def list_models(self) -> list[str]:
        """Return a list of locally available model names."""
        url = f"{self.base_url}/api/tags"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode("utf-8"))
                return [m["name"] for m in data.get("models", [])]
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Could not reach Ollama at {self.base_url}."
            ) from e
