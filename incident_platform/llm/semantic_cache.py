"""Two-level semantic cache.

L1  exact match on the SHA-256 of the normalised cache key (O(1)).
L2  cosine similarity over a hashed bag-of-words embedding. A near-duplicate
    incident ("...CrashLoopBackOff again") reuses the earlier answer instead
    of spending tokens.

**The embedding is a hashing trick, not a trained model.** Each token is
hashed to one of ``dim`` buckets with a hashed +/-1 sign (signed feature
hashing), and the vector is L2-normalised. It captures lexical overlap, not
meaning. That is enough to demonstrate the pattern; swapping in a real
embedding model only changes ``embed()``.

**Cache on content, not on the prompt.** Callers pass a content-focused
``cache_key`` (the incident's symptom text), *not* the full templated prompt.
Embedding the full prompt made two unrelated incidents look 0.91-similar,
because the shared template boilerplate drowned out the symptoms. See ADR-03.
"""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_\-\.]*")


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def embed(text: str, dim: int = 512) -> list[float]:
    vec = [0.0] * dim
    for token in tokenize(text):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dim
        sign = 1.0 if digest[4] & 1 else -1.0
        vec[index] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    return [v / norm for v in vec] if norm else vec


def cosine(a: list[float], b: list[float]) -> float:
    # Both vectors are already L2-normalised.
    return sum(x * y for x, y in zip(a, b))


def similarity(text_a: str, text_b: str, dim: int = 512) -> float:
    return cosine(embed(text_a, dim), embed(text_b, dim))


@dataclass
class CacheHit:
    value: Any
    layer: str  # "L1" | "L2"
    similarity: float
    matched_key: str


@dataclass
class _Entry:
    namespace: str
    key: str
    vector: list[float]
    value: Any


class SemanticCache:
    def __init__(self, threshold: float = 0.85, dim: int = 512):
        self.threshold = threshold
        self.dim = dim
        self._l1: dict[str, _Entry] = {}
        self._l2: list[_Entry] = []
        self.hits_l1 = 0
        self.hits_l2 = 0
        self.misses = 0

    @staticmethod
    def _normalise(key: str) -> str:
        return " ".join(tokenize(key))

    def _l1_key(self, namespace: str, key: str) -> str:
        return hashlib.sha256(f"{namespace}\x00{self._normalise(key)}".encode("utf-8")).hexdigest()

    def get(self, namespace: str, key: str) -> CacheHit | None:
        exact = self._l1.get(self._l1_key(namespace, key))
        if exact is not None:
            self.hits_l1 += 1
            return CacheHit(copy.deepcopy(exact.value), "L1", 1.0, exact.key)

        query = embed(key, self.dim)
        best: tuple[float, _Entry] | None = None
        for entry in self._l2:
            if entry.namespace != namespace:
                continue
            score = cosine(query, entry.vector)
            if best is None or score > best[0]:
                best = (score, entry)
        if best is not None and best[0] >= self.threshold:
            self.hits_l2 += 1
            return CacheHit(copy.deepcopy(best[1].value), "L2", best[0], best[1].key)

        self.misses += 1
        return None

    def put(self, namespace: str, key: str, value: Any) -> None:
        entry = _Entry(namespace, key, embed(key, self.dim), copy.deepcopy(value))
        self._l1[self._l1_key(namespace, key)] = entry
        self._l2.append(entry)

    def __len__(self) -> int:
        return len(self._l1)
