import contextlib
import importlib.util
import io
import unittest

import _path  # noqa: F401

import main
from agents.triage_agent import TriageAgent
from config import Settings
from guardrails import PIIDetector
from llm.llm_backend import _PLAN_RULES, _TRIAGE_RULES
from mcp_server import TOOL_SPECS
from orchestrator import IncidentPlatform
from state import Incident

SPACY_AVAILABLE = importlib.util.find_spec("spacy") is not None


class RegexLayerTests(unittest.TestCase):
    def setUp(self):
        self.d = PIIDetector("off")

    def assertRedacts(self, text, expected_counts):
        _, counts = self.d.redact(text)
        self.assertEqual(counts, expected_counts, text)

    def test_fixed_shape_pii(self):
        cases = {
            "mail ops@cloudscale.example now": {"EMAIL": 1},
            "client connected from 10.0.3.17": {"IP": 1},
            "client fe80::1ff:fe23:4567:890a": {"IP": 1},
            "call (415) 555-0132 or +44 20 7946 0958": {"PHONE": 2},
            "reach me (+44 20 7946 0958) today": {"PHONE": 1},
            "card 4111 1111 1111 1111": {"CARD": 1},
        }
        for text, counts in cases.items():
            with self.subTest(text=text):
                self.assertRedacts(text, counts)

    def test_secret_formats(self):
        for text in (
            "Authorization: Bearer abc.def.ghijkl",
            "key sk-proj-abcdefghijklmnop",
            "aws AKIAABCDEFGHIJKLMNOP",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signature",
            "github ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "slack xoxb-1234567890-abcdefghij",
            "gitlab glpat-abcdefghij0123456789",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        ):
            with self.subTest(text=text[:30]):
                self.assertRedacts(text, {"SECRET": 1})

    def test_benign_numbers_are_left_alone(self):
        for text in (
            "upgraded libfoo to 1.2.3.4 yesterday",   # version context, not a host
            "card-like id 4111 1111 1111 1112",      # fails the Luhn check
            "on 2026-09-25, restarts=14 in 20m",
            "p95 1840ms vs SLO 400ms; 11 pods evicted in 10m",
            "order 12345 678 90 shipped",
        ):
            with self.subTest(text=text):
                self.assertRedacts(text, {})

    def test_regex_only_mode_misses_names(self):
        self.assertRedacts("reported by Priya Sharma", {})


class HeuristicNERTests(unittest.TestCase):
    def setUp(self):
        self.d = PIIDetector("heuristic")

    def test_names_after_context_cues(self):
        for text, name in (
            ("Reported by Priya Sharma at 10:05", "Priya Sharma"),
            ("cc: Wei Zhang", "Wei Zhang"),
            ("escalated to Kofi", "Kofi"),
            ("contact Jane Doe on +44 20 7946 0958", "Jane Doe"),
            ("Thanks, Oluwaseun Adeyemi", "Oluwaseun Adeyemi"),
        ):
            with self.subTest(text=text):
                names = [f.text for f in self.d.find(text) if f.label == "PERSON"]
                self.assertEqual(names, [name])

    def test_names_do_not_span_line_breaks(self):
        names = [f.text for f in self.d.find("Login failures reported by Priya Sharma\nReported at 10:05")
                 if f.label == "PERSON"]
        self.assertEqual(names, ["Priya Sharma"])

    def test_gazetteer_first_name_plus_surname_without_cue(self):
        redacted, counts = self.d.redact("login failures for Carlos Mendez since noon")
        self.assertEqual(counts, {"PERSON": 1})
        self.assertEqual(redacted, "login failures for [REDACTED_PERSON] since noon")

    def test_capitalised_tech_words_are_not_names(self):
        for text in (
            "reported by Node ip-10-0-7-22",
            "Kubernetes Pods evicted; contact Support Team",
            "user Admin locked; owner Platform",
            "Elevated p95 latency on search-api",
            "NullPointerException in OrderPricingV2.apply",
        ):
            with self.subTest(text=text):
                self.assertEqual([f for f in self.d.find(text) if f.label == "PERSON"], [])

    def test_no_false_positives_across_all_demo_text(self):
        """Adding NER must not redact anything new in the 10 scripted scenarios."""
        texts = []
        for sc in main.build_scenarios():
            texts += [sc.incident.title, *map(str, sc.incident.telemetry.values()), *sc.logs, *sc.signals,
                      TriageAgent._prompt(sc.incident, {"logs": sc.logs, "signals": sc.signals}, [])]
        texts += [r[2] for r in _TRIAGE_RULES] + [s for _, steps in _PLAN_RULES.values() for s in steps]
        texts += [t.description + " " + t.blast_radius for t in TOOL_SPECS]
        found = {(f.label, f.text) for t in texts for f in self.d.find(t)}
        self.assertEqual(found, {("IP", "10.0.3.17"), ("IP", "10.0.9.4"), ("EMAIL", "jane.doe@cloudscale.example")})

    def test_overlapping_findings_are_merged(self):
        # The email contains a first name; it must be redacted once, as EMAIL.
        self.assertEqual(self.d.redact("contact priya.sharma@corp.example")[1], {"EMAIL": 1})


class SpacyLayerTests(unittest.TestCase):
    @unittest.skipIf(SPACY_AVAILABLE, "spaCy is installed; fallback path not exercised")
    def test_missing_spacy_falls_back_with_warning(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            d = PIIDetector("spacy")
        self.assertEqual(d.name, "regex+heuristic-ner")
        self.assertIn("spaCy NER requested but unavailable", err.getvalue())
        self.assertEqual(d.redact("reported by Priya Sharma")[1], {"PERSON": 1})

    @unittest.skipUnless(SPACY_AVAILABLE, "spaCy not installed")
    def test_spacy_adds_names_without_cues_or_gazetteer(self):
        d = PIIDetector("spacy")
        if d.spacy is None:
            self.skipTest("spaCy installed but model en_core_web_sm is missing")
        self.assertIn("spacy", d.name)
        # Neither a cue nor a gazetteer first name: only the statistical model can catch this.
        _, counts = d.redact("The outage was first noticed by Bartholomew Quigley in the Leeds office.")
        self.assertEqual(counts.get("PERSON"), 1)

    @unittest.skipUnless(SPACY_AVAILABLE, "spaCy not installed")
    def test_spacy_false_positives_are_filtered_on_demo_text(self):
        d = PIIDetector("spacy")
        if d.spacy is None:
            self.skipTest("spaCy installed but model en_core_web_sm is missing")
        texts = []
        for sc in main.build_scenarios():
            texts += [sc.incident.title, *map(str, sc.incident.telemetry.values()), *sc.logs, *sc.signals,
                      TriageAgent._prompt(sc.incident, {"logs": sc.logs, "signals": sc.signals}, [])]
        texts += [s for _, steps in _PLAN_RULES.values() for s in steps]
        people = {f.text for t in texts for f in d.find(t) if f.label == "PERSON"}
        # The one real name (INC-1002) is found; prompt words and ops evidence are not.
        self.assertEqual(people, {"Bartholomew Quigley"}, "spaCy must not redact prompt words or ops evidence")

    @unittest.skipUnless(SPACY_AVAILABLE, "spaCy not installed")
    def test_scripted_demo_credits_spacy(self):
        settings = Settings(PII_NER="spacy")
        platform = IncidentPlatform(settings=settings)
        if platform.guardrails.pii.spacy is None:
            self.skipTest("model en_core_web_sm is missing")
        from hitl import AutoApprovalChannel
        from orchestrator import IncidentOrchestrator
        sc = main.build_scenarios()[1]  # INC-1002
        main.prepare_scenario(platform, sc)
        IncidentOrchestrator(platform, AutoApprovalChannel({"INC-1002": True})).handle(sc.incident)
        self.assertEqual(sc.incident.notes["pii_sources"].get("PERSON/spacy-ner"), 1)
        self.assertNotIn("Bartholomew", str(platform.audit.entries))

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            PIIDetector("magic")


class SourceAttributionTests(unittest.TestCase):
    def test_each_finding_names_its_layer(self):
        from guardrails import GuardrailMiddleware
        _, by_label, by_source = GuardrailMiddleware("heuristic").redact_pii_detailed(
            "reported by Priya Sharma, mail ops@corp.example")
        self.assertEqual(by_label, {"EMAIL": 1, "PERSON": 1})
        self.assertEqual(by_source, {"EMAIL/regex": 1, "PERSON/heuristic-ner": 1})

    @unittest.skipUnless(SPACY_AVAILABLE, "spaCy not installed")
    def test_spacy_only_catch_is_attributed_to_spacy(self):
        d = PIIDetector("spacy")
        if d.spacy is None:
            self.skipTest("model en_core_web_sm is missing")
        sources = {f.source for f in d.find("The outage was first noticed by Bartholomew Quigley.")}
        self.assertEqual(sources, {"spacy-ner"})

    def test_sources_reach_audit_and_notes(self):
        _, results = main.run_demo(audit_path=None, verbose=False)
        inc = next(sc.incident for sc, _ in results if sc.incident.incident_id == "INC-1005")
        self.assertEqual(inc.notes["pii_sources"], {"EMAIL/regex": 1, "IP/regex": 1})


class AuditRedactionTests(unittest.TestCase):
    def test_title_with_pii_is_redacted_in_audit(self):
        platform = IncidentPlatform(settings=Settings())
        inc = Incident("INC-P1", "Priya Sharma (priya@corp.example) cannot log in", "P2",
                       {"symptoms": "login failures"}, {"namespace": "web", "workload": "auth", "service": "auth"})
        platform.store.put(inc)
        dump = str(platform.audit.entries)
        self.assertNotIn("Priya", dump)
        self.assertNotIn("priya@corp.example", dump)
        self.assertIn("[REDACTED_PERSON]", dump)


if __name__ == "__main__":
    unittest.main()
