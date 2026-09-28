import unittest

import _path  # noqa: F401

from agents import TriageAgent
from config import Settings
from llm import MockLLMBackend, ModelRouter, ResilientBackend, SemanticCache, get_backend, similarity
from state import Incident


class SemanticCacheTests(unittest.TestCase):
    def test_l1_exact_hit_ignores_case_and_punctuation(self):
        cache = SemanticCache(threshold=0.85)
        cache.put("ns", "Pod CrashLoopBackOff!", {"v": 1})
        hit = cache.get("ns", "pod crashloopbackoff")
        self.assertEqual((hit.layer, hit.value), ("L1", {"v": 1}))

    def test_l2_near_duplicate_hit(self):
        cache = SemanticCache(threshold=0.85)
        cache.put("ns", "checkout-service pods stuck in CrashLoopBackOff restarts=14 liveness probe failed", {"v": 1})
        hit = cache.get("ns", "checkout-service pods stuck in CrashLoopBackOff again restarts=14 liveness probe failed")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.layer, "L2")
        self.assertGreaterEqual(hit.similarity, 0.85)

    def test_namespaces_do_not_mix(self):
        cache = SemanticCache()
        cache.put("triage", "same text", {"v": 1})
        self.assertIsNone(cache.get("planner", "same text"))

    def test_cached_values_are_copies(self):
        cache = SemanticCache()
        cache.put("ns", "k", {"steps": [1]})
        cache.get("ns", "k").value["steps"].append(2)
        self.assertEqual(cache.get("ns", "k").value, {"steps": [1]})

    def test_regression_full_prompt_vs_content_key(self):
        """The bug from ADR-03: shared template boilerplate made different incidents
        look alike. Content keys keep them apart."""
        a = Incident("A", "checkout-service pods stuck in CrashLoopBackOff", "P1",
                     {"alert": "KubePodCrashLooping", "symptoms": "restarts=14 liveness probe failed"})
        b = Incident("B", "Elevated p95 latency on search-api", "P2",
                     {"alert": "LatencySLOBurn", "symptoms": "p95 latency 1840ms vs SLO 400ms"})
        template = ("TASK: TRIAGE Role: triage agent for production Kubernetes incidents. Determine the most "
                    "likely root cause from the evidence below. Respond with JSON keys: root_cause (string), "
                    "confidence (float 0-1), category (one of pod_crashloop, resource_exhaustion, "
                    "bad_deployment, node_disk_pressure, latency_degradation, unknown). EVIDENCE: {}")
        full = similarity(template.format(TriageAgent.cache_key(a)), template.format(TriageAgent.cache_key(b)))
        content = similarity(TriageAgent.cache_key(a), TriageAgent.cache_key(b))
        self.assertLess(content, 0.85)
        self.assertGreater(full, content)


class BackendSelectionTests(unittest.TestCase):
    def test_default_is_mock(self):
        self.assertIsInstance(get_backend(Settings()), MockLLMBackend)

    def test_flag_without_key_stays_mock(self):
        self.assertIsInstance(get_backend(Settings(USE_REAL_LLM=True, OPENAI_API_KEY=None)), MockLLMBackend)

    def test_key_without_flag_stays_mock(self):
        self.assertIsInstance(get_backend(Settings(USE_REAL_LLM=False, OPENAI_API_KEY="sk-x")), MockLLMBackend)

    def test_resilient_backend_falls_back(self):
        class Broken:
            name = "broken"

            def complete(self, prompt, model):
                raise ConnectionError("provider down")

        backend = ResilientBackend(Broken(), MockLLMBackend())
        reply = backend.complete("TASK: TRIAGE\nEVIDENCE:\nOOMKilled", "gpt-4o")
        self.assertEqual(reply.backend, "mock")
        self.assertEqual(backend.fallbacks, 1)


class ModelOverrideTests(unittest.TestCase):
    def test_model_names_can_be_overridden_from_env(self):
        import os
        from unittest import mock

        import config
        env = {"INCIDENT_PLATFORM_ACCURACY_MODEL": "my-big-model", "INCIDENT_PLATFORM_COST_MODEL": "my-small-model"}
        with mock.patch.dict(os.environ, env):
            s = config.load_settings()
        self.assertEqual((s.ACCURACY_TIER.name, s.COST_TIER.name), ("my-big-model", "my-small-model"))
        self.assertEqual(s.COST_TIER.input_cost_per_1k, Settings().COST_TIER.input_cost_per_1k)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(config.load_settings().ACCURACY_TIER.name, Settings().ACCURACY_TIER.name)


class PromptGuidanceTests(unittest.TestCase):
    def test_triage_prompt_defines_every_category_and_tools_say_when_to_use_them(self):
        from agents.triage_agent import CATEGORY_DEFINITIONS, TriageAgent
        from mcp_server import TOOL_SPECS
        inc = Incident("INC-P", "t", "P1", {"symptoms": "s"})
        prompt = TriageAgent._prompt(inc, {}, [])
        for name, definition in CATEGORY_DEFINITIONS.items():
            self.assertIn(f"- {name}: {definition}", prompt)
        self.assertLess(prompt.index("CATEGORIES:"), prompt.index("EVIDENCE:"))  # mock reads evidence only
        for spec in TOOL_SPECS:
            if not spec.read_only:
                self.assertIn("Use ", spec.description, spec.name)


class DotenvTests(unittest.TestCase):
    def test_parses_file_without_overriding_existing_variables(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest import mock

        import config
        content = ("\ufeff# comment line\n\n"
                   "export DOTENV_T_A=plain\n"
                   "DOTENV_T_B = \"quoted value\"\n"
                   "DOTENV_T_C=keep # trailing comment\n"
                   "DOTENV_T_D=from-file\n"
                   "not a setting\n"
                   "1BAD=ignored\n")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".env"
            path.write_text(content, encoding="utf-8")
            with mock.patch.dict(os.environ, {"DOTENV_T_D": "from-shell"}):
                loaded = config.load_dotenv(path)
                values = {k: os.environ.get(k) for k in ("DOTENV_T_A", "DOTENV_T_B", "DOTENV_T_C", "DOTENV_T_D")}
        self.assertEqual(sorted(loaded), ["DOTENV_T_A", "DOTENV_T_B", "DOTENV_T_C"])
        self.assertEqual(values, {"DOTENV_T_A": "plain", "DOTENV_T_B": "quoted value",
                                  "DOTENV_T_C": "keep", "DOTENV_T_D": "from-shell"})

    def test_missing_file_is_fine_and_tests_never_load_dotenv(self):
        import config
        self.assertEqual(config.load_dotenv(config.ENV_FILE.with_name("does-not-exist.env")), [])
        self.assertTrue(config.DOTENV_STATUS.startswith("disabled"))
        self.assertFalse(config.SETTINGS.USE_REAL_LLM)


class RouterTests(unittest.TestCase):
    def test_routing(self):
        s = Settings()
        r = ModelRouter(s.ACCURACY_TIER, s.COST_TIER)
        self.assertEqual(r.route("P1").name, s.ACCURACY_TIER.name)
        self.assertEqual(r.route("P2").name, s.COST_TIER.name)
        self.assertEqual(r.route("P2", "high").name, s.ACCURACY_TIER.name)


if __name__ == "__main__":
    unittest.main()
