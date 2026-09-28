"""LLM provider fallback chain: OpenAI -> Anthropic -> mock (ADR-05). No network, no SDKs needed."""

import sys
import types
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock

import _path  # noqa: F401

from config import Settings
from llm import FallbackChainBackend, LLMResponse, MockLLMBackend, get_backend
from llm.anthropic_backend import AnthropicLLMBackend, AnthropicRefusal
from llm.llm_backend import _anthropic_model_map
from state import BreakerRegistry

TRIAGE_PROMPT = "TASK: TRIAGE\nEVIDENCE:\nCrashLoopBackOff"


class Down:
    """A provider that always fails, counting how often it was really called."""

    def __init__(self, name="openai", exc=ConnectionError("provider down")):
        self.name, self.exc, self.calls = name, exc, 0

    def complete(self, prompt, model):
        self.calls += 1
        raise self.exc


class Echo:
    """A provider that answers like the mock but reports its own name and the model it was asked for."""

    def __init__(self, name):
        self.name, self.models = name, []

    def complete(self, prompt, model):
        self.models.append(model)
        r = MockLLMBackend().complete(prompt, model)
        return LLMResponse(r.text, r.tokens_in, r.tokens_out, self.name)


class FakeAnthropicClient:
    """Records calls to messages.create / beta.messages.create and returns a canned Message."""

    def __init__(self, stop_reason="end_turn", text='{"root_cause": "x", "confidence": 0.9, "category": "unknown"}'):
        self.calls = []

        def create(kind):
            def _create(**kwargs):
                self.calls.append((kind, kwargs))
                return SimpleNamespace(
                    stop_reason=stop_reason, stop_details=SimpleNamespace(category="cyber"),
                    model=kwargs["model"],
                    content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
                    usage=SimpleNamespace(input_tokens=120, output_tokens=30),
                )
            return _create

        self.messages = SimpleNamespace(create=create("messages"))
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=create("beta")))


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.s = Settings()

    def test_openai_failure_is_answered_by_claude_with_the_matching_tier(self):
        openai, claude = Down(), Echo("anthropic")
        chain = FallbackChainBackend([(openai, None), (claude, _anthropic_model_map(self.s)), (MockLLMBackend(), None)])
        accurate = chain.complete(TRIAGE_PROMPT, self.s.ACCURACY_TIER.name)
        cheap = chain.complete(TRIAGE_PROMPT, self.s.COST_TIER.name)
        self.assertEqual(claude.models, [self.s.ANTHROPIC_ACCURACY_TIER.name, self.s.ANTHROPIC_COST_TIER.name])
        self.assertEqual((accurate.backend, accurate.model), ("anthropic", "claude-opus-5"))
        self.assertEqual(cheap.model, "claude-haiku-4-5")
        self.assertIn("openai: ConnectionError: provider down", accurate.fallback_error)
        self.assertEqual(chain.name, "openai->anthropic->mock")
        self.assertEqual(chain.fallbacks, 2)

    def test_both_providers_down_falls_through_to_the_mock(self):
        chain = FallbackChainBackend([(Down("openai"), None), (Down("anthropic", TimeoutError("slow")), None),
                                      (MockLLMBackend(), None)])
        r = chain.complete(TRIAGE_PROMPT, "gpt-4o")
        self.assertEqual(r.backend, "mock")
        self.assertIn("openai: ConnectionError", r.fallback_error)
        self.assertIn("anthropic: TimeoutError: slow", r.fallback_error)

    def test_healthy_primary_is_not_marked_as_fallback(self):
        chain = FallbackChainBackend([(Echo("openai"), None), (MockLLMBackend(), None)])
        r = chain.complete(TRIAGE_PROMPT, "gpt-4o")
        self.assertEqual((r.backend, r.model, r.fallback_error), ("openai", "gpt-4o", None))

    def test_provider_breaker_skips_a_failing_provider_instantly(self):
        openai = Down()
        changes = []
        breakers = BreakerRegistry(failure_threshold=3, recovery_timeout=60,
                                   on_state_change=lambda n, a, b: changes.append((n, b.value)))
        chain = FallbackChainBackend([(openai, None), (MockLLMBackend(), None)], breakers)
        for _ in range(5):
            chain.complete(TRIAGE_PROMPT, "gpt-4o")
        self.assertEqual(openai.calls, 3)                      # calls 4 and 5 never reached OpenAI
        self.assertEqual(changes, [("llm:openai", "OPEN")])
        self.assertIn("CircuitOpenError", chain.last_error)

    def test_last_link_errors_propagate(self):
        chain = FallbackChainBackend([(Down("a"), None), (Down("b"), None)])
        with self.assertRaises(ConnectionError):
            chain.complete(TRIAGE_PROMPT, "m")


class AnthropicBackendTests(unittest.TestCase):
    def test_opus_uses_server_side_refusal_fallback_and_no_sampling_params(self):
        client = FakeAnthropicClient()
        r = AnthropicLLMBackend("sk-ant-test", client=client).complete(TRIAGE_PROMPT, "claude-opus-5")
        kind, kwargs = client.calls[0]
        self.assertEqual(kind, "beta")
        self.assertEqual((kwargs["betas"], kwargs["fallbacks"]), (["server-side-fallback-2026-07-01"], "default"))
        self.assertNotIn("temperature", kwargs)
        self.assertEqual(kwargs["messages"], [{"role": "user", "content": TRIAGE_PROMPT}])
        self.assertIn("JSON", kwargs["system"])
        self.assertEqual((r.text, r.tokens_in, r.tokens_out, r.backend, r.model),
                         ('{"root_cause": "x", "confidence": 0.9, "category": "unknown"}', 120, 30,
                          "anthropic", "claude-opus-5"))  # thinking block ignored, text kept

    def test_haiku_uses_the_plain_messages_endpoint(self):
        client = FakeAnthropicClient()
        AnthropicLLMBackend("sk-ant-test", client=client).complete(TRIAGE_PROMPT, "claude-haiku-4-5")
        kind, kwargs = client.calls[0]
        self.assertEqual(kind, "messages")
        self.assertNotIn("fallbacks", kwargs)

    def test_refusal_raises_so_the_chain_moves_on(self):
        backend = AnthropicLLMBackend("sk-ant-test", client=FakeAnthropicClient(stop_reason="refusal"))
        with self.assertRaises(AnthropicRefusal):
            backend.complete(TRIAGE_PROMPT, "claude-opus-5")
        chain = FallbackChainBackend([(backend, None), (MockLLMBackend(), None)])
        r = chain.complete(TRIAGE_PROMPT, "claude-opus-5")
        self.assertEqual(r.backend, "mock")
        self.assertIn("AnthropicRefusal", r.fallback_error)


class GetBackendTests(unittest.TestCase):
    def _fake_sdk(self):
        fake = types.ModuleType("anthropic")
        fake.Anthropic = lambda **kwargs: FakeAnthropicClient()
        return fake

    def test_chain_is_built_from_the_keys_present(self):
        base = replace(Settings(), USE_REAL_LLM=True)
        with mock.patch.dict(sys.modules, {"anthropic": self._fake_sdk()}):
            only_claude = get_backend(replace(base, ANTHROPIC_API_KEY="sk-ant-x"))
        self.assertEqual(only_claude.name, "anthropic->mock")
        self.assertIsInstance(get_backend(base), MockLLMBackend)                        # no keys at all
        self.assertIsInstance(get_backend(replace(Settings(), ANTHROPIC_API_KEY="k")), MockLLMBackend)  # switch off

    def test_missing_anthropic_sdk_is_skipped_not_fatal(self):
        with mock.patch.dict(sys.modules, {"anthropic": None}):  # makes `import anthropic` raise ImportError
            backend = get_backend(replace(Settings(), USE_REAL_LLM=True, ANTHROPIC_API_KEY="sk-ant-x"))
        self.assertIsInstance(backend, MockLLMBackend)


class BillingTests(unittest.TestCase):
    def test_a_claude_fallback_is_billed_at_claude_prices(self):
        import main
        from hitl import AutoApprovalChannel
        from orchestrator import IncidentOrchestrator, IncidentPlatform
        s = Settings()
        chain = FallbackChainBackend([(Down(), None), (Echo("anthropic"), _anthropic_model_map(s)),
                                      (MockLLMBackend(), None)])
        platform = IncidentPlatform(settings=s, backend=chain)
        sc = next(x for x in main.build_scenarios() if x.incident.incident_id == "INC-1001")
        main.prepare_scenario(platform, sc)
        IncidentOrchestrator(platform, AutoApprovalChannel()).handle(sc.incident)
        calls = [e["payload"] for e in platform.audit.filter(action="llm_call")]
        self.assertEqual({c["model"] for c in calls}, {"claude-opus-5"})
        self.assertEqual({c["routed_model"] for c in calls}, {"gpt-4o"})
        rec = platform.profiler.records[0]
        expected = (rec.tokens_in / 1000 * s.ANTHROPIC_ACCURACY_TIER.input_cost_per_1k
                    + rec.tokens_out / 1000 * s.ANTHROPIC_ACCURACY_TIER.output_cost_per_1k)
        self.assertAlmostEqual(rec.cost_usd, expected)
        self.assertEqual(rec.model, "claude-opus-5")


if __name__ == "__main__":
    unittest.main()
