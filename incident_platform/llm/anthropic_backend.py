"""Anthropic Claude backend: the second provider in the LLM fallback chain.

Optional, like the OpenAI backend: it needs ``pip install anthropic`` and an
``ANTHROPIC_API_KEY`` (plus ``INCIDENT_PLATFORM_USE_REAL_LLM=true``). The SDK is
imported lazily, so the platform still runs on the standard library alone.

Request shape (Anthropic Messages API):

* ``system`` carries the same JSON-only instruction the OpenAI backend uses.
  There is no assistant prefill (current Claude models reject it), so replies are
  parsed by ``parse_json_reply``, which tolerates code fences. An unparseable reply
  is an ``LLMOutputError`` -> the incident escalates, never a guess.
* No ``temperature``: Claude Opus 5 rejects sampling parameters (400).
* ``stop_reason`` is checked before reading content. A policy refusal raises
  ``AnthropicRefusal``, so the chain moves on to the next provider.
* On models that support it, Anthropic's **server-side refusal fallback** is on
  (``fallbacks="default"``, beta ``server-side-fallback-2026-07-01``): a declined
  request is re-run on Anthropic's recommended fallback model inside the same call.
"""

from __future__ import annotations

from typing import Any

from .llm_backend import SYSTEM_PROMPT, LLMResponse

# Models on which the server-side refusal fallback parameter is used.
SERVER_FALLBACK_MODELS = frozenset({"claude-opus-5", "claude-fable-5-1"})
SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000  # generous: adaptive thinking on Opus 5 counts towards it


class AnthropicRefusal(Exception):
    """Claude declined the request (``stop_reason == "refusal"``)."""


class AnthropicLLMBackend:
    name = "anthropic"

    def __init__(self, api_key: str, timeout: float = 20.0, client: Any = None):
        if client is None:
            import anthropic  # optional dependency

            # One SDK-level retry; our fallback chain handles the rest.
            client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=1)
        self._client = client

    def complete(self, prompt: str, model: str) -> LLMResponse:
        request = {
            "model": model,
            "max_tokens": MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        if model in SERVER_FALLBACK_MODELS:
            response = self._client.beta.messages.create(
                betas=[SERVER_FALLBACK_BETA], fallbacks="default", **request)
        else:
            response = self._client.messages.create(**request)

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise AnthropicRefusal(f"Claude declined the request (category: {category})")

        # Content can also hold thinking / fallback blocks: keep the text only.
        text = "".join(block.text for block in response.content if block.type == "text")
        usage = response.usage
        return LLMResponse(text, usage.input_tokens, usage.output_tokens, self.name,
                           model=getattr(response, "model", None) or model)
