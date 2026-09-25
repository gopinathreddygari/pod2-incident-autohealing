"""Layered PII detection: regex rules + heuristic NER (+ optional spaCy NER).

Layer 1 -- **regex rules** for PII with a fixed shape: emails, IPv4/IPv6,
           phone numbers, card numbers (Luhn-checked), and credential formats
           (OpenAI/AWS/GitHub/Slack/GitLab keys, JWTs, bearer tokens, private keys).
Layer 2 -- **heuristic NER** (standard library, always on) for person names,
           which have no fixed shape:
             * context cues: "reported by Jane Doe", "contact: Priya", "cc Wei Zhang"
             * a first-name gazetteer: "Carlos Mendez" matches without any cue
           A stoplist keeps capitalised tech words ("Node", "Kubernetes") out.
Layer 3 -- **spaCy NER** (optional; ``INCIDENT_PLATFORM_PII_NER=spacy`` and
           ``pip install spacy`` + ``python -m spacy download en_core_web_sm``).
           It adds statistical PERSON detection. If spaCy is missing, a warning
           is printed and layers 1-2 still run.

All layers return character spans; overlapping findings are merged (earliest,
then longest wins) and replaced with ``[REDACTED_<LABEL>]``.

Design bias: for PII, a false positive (redacting a version number) is cheap,
while a false negative (a customer's name sent to a provider) is not. So
ambiguous shapes are redacted unless there is clear evidence they are benign.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class PIIFinding:
    start: int
    end: int
    label: str
    source: str  # "regex" | "heuristic-ner" | "spacy-ner"
    text: str


# --------------------------------------------------------------------------
# Layer 1: regex rules (+ validators)
# --------------------------------------------------------------------------

_VERSION_CUE = re.compile(r"\b(v|ver|version|release|upgrad\w*|downgrad\w*|bump\w*|pinned|semver)\b", re.I)


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_ok(candidate: str, text: str, start: int) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    # "upgraded libfoo to 1.2.3.4" is a version, not a host.
    return not _VERSION_CUE.search(text[max(0, start - 25):start])


def _ipv6_ok(candidate: str) -> bool:
    if candidate.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


def _phone_ok(candidate: str) -> bool:
    digits = sum(c.isdigit() for c in candidate)
    separators = sum(c in " .-()" for c in candidate)
    return 9 <= digits <= 15 and (candidate.startswith("+") or separators >= 2)


# (label, pattern, validator(match_text, full_text, start) -> bool | None)
Validator = Callable[[str, str, int], bool]

REGEX_RULES: list[tuple[str, re.Pattern[str], Validator | None]] = [
    ("SECRET", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), None),
    ("SECRET", re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}=*", re.I), None),
    ("SECRET", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None),  # JWT
    ("SECRET", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), None),                    # OpenAI-style
    ("SECRET", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),                      # AWS access key id
    ("SECRET", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None),            # GitHub
    ("SECRET", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), None),            # Slack
    ("SECRET", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), None),                # GitLab
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("CARD", re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"), lambda m, t, s: _luhn_ok(m)),
    ("IP", re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])"), lambda m, t, s: _ipv6_ok(m)),
    ("IP", re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])"), _ipv4_ok),
    ("PHONE", re.compile(r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]\d{1,4}){1,4}(?!\w)"),
     lambda m, t, s: _phone_ok(m)),
]


def regex_findings(text: str) -> list[PIIFinding]:
    out = []
    for label, pattern, validator in REGEX_RULES:
        for m in pattern.finditer(text):
            if validator is None or validator(m.group(0), text, m.start()):
                out.append(PIIFinding(m.start(), m.end(), label, "regex", m.group(0)))
    return out


# --------------------------------------------------------------------------
# Layer 2: heuristic NER for person names (standard library)
# --------------------------------------------------------------------------

_NAME = r"(?:Mc|Mac|O['’])?[A-Z][a-z]+(?:-[A-Z][a-z]+)?"

# Case-insensitive cue, case-sensitive name that follows it.
_CUE_RE = re.compile(
    r"(?i:\b(?:reported|raised|opened|submitted|filed|created|approved|signed)\s+by"
    r"|\b(?:assigned|escalated|forwarded|handed\s+over)\s+to"
    r"|\bcontact(?:ed)?|\bcc|\bowner|\breporter|\brequester|\bcustomer|\buser|\bname"
    r"|\bon-?call(?:\s+engineer)?|\bpaged|\bdear|\bhi|\bhello|\bthanks|\bregards|\bcheers)"
    rf"\s*[:,\-]?\s+({_NAME}(?:[ \t]+{_NAME}){{0,2}})"
)
_PAIR_RE = re.compile(rf"\b({_NAME})[ \t]+({_NAME})\b")  # names never span a line break

# Capitalised words that are not names in an ops context.
STOPWORDS = frozenset("""
A An The This That These Those It We You They He She I Our Your Their Its
Node Nodes Pod Pods Service Services Deployment Cluster Namespace Container Containers Kubelet
Kubernetes Prometheus Datadog Grafana Terraform Docker Linux Windows Redis Postgres Kafka
Error Errors Alert Alerts Warning Critical High Low Medium Elevated Disk Memory Latency Rate
Team Support Ops Platform Admin Root System Production Staging Prod Dev Cloud Global Networks
Monday Tuesday Wednesday Thursday Friday Saturday Sunday
January February March April June July August September October November December
Please Thanks Hello Hi Regards Dear Note Update Fix Issue Incident Ticket Request Login
Respond Determine Choose Lower Cordon Drain Roll Rolling Scale Restart Watch Freeze Prune Open
Fetch Correlate Evidence Role Task
""".split())

# Common first names across regions. Deliberately excludes names that are also
# everyday words (Will, May, Mark, Grace, Hope, Rose, Max, Bill, Chase, Frank, ...).
FIRST_NAMES = frozenset("""
James John Robert Michael David Richard Joseph Thomas Charles Daniel Matthew Anthony Steven
Paul Andrew Joshua Kevin Brian George Edward Ronald Timothy Jason Jeffrey Ryan Jacob Gary
Nicholas Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel Gregory Alexander
Patrick Jack Dennis Jerry Tyler Aaron Henry Adam Nathan Peter Zachary Kyle Noah Ethan Liam
Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Sarah Karen Lisa Nancy Betty
Sandra Margaret Ashley Kimberly Emily Donna Michelle Carol Amanda Melissa Deborah Stephanie
Rebecca Sharon Laura Cynthia Kathleen Amy Angela Shirley Anna Brenda Pamela Emma Nicole Helen
Samantha Katherine Christine Rachel Carolyn Janet Catherine Maria Heather Diane Julie Olivia
Sophia Isabella Mia Charlotte Amelia Jane Joan Alice Claire Lucy Sophie Chloe Hannah Zoe
Priya Aarav Vivaan Aditya Arjun Rohan Rahul Amit Anil Sunil Vijay Sanjay Ravi Suresh Ramesh
Deepak Arun Kiran Pooja Neha Anjali Kavya Divya Sneha Lakshmi Meera Aisha Fatima Omar Ahmed
Mohammed Ali Hassan Yusuf Ibrahim Layla Zainab Carlos Jose Luis Juan Miguel Jorge Pedro Diego
Alejandro Sofia Lucia Valentina Camila Gabriela Isabel Elena Carmen Wei Jing Li Ming Hui Yan
Chen Xin Yuki Hiroshi Kenji Haruto Sakura Aiko Minjun Jiwoo Seo Hans Lukas Felix Leon Jonas
Anja Katrin Lena Pierre Louis Hugo Camille Chloé Marco Luca Giulia Francesca Olga Ivan Dmitri
Sergei Anastasia Natasha Kwame Kofi Amara Chidi Ngozi Oluwaseun Tunde Zanele Thabo
""".split())


def heuristic_name_findings(text: str) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _CUE_RE.finditer(text):
        tokens = m.group(1).split()
        # Trim stopwords at the edges ("reported by Jane Doe Team" -> "Jane Doe").
        while tokens and tokens[-1] in STOPWORDS:
            tokens.pop()
        if not tokens or tokens[0] in STOPWORDS:
            continue
        name = " ".join(tokens)
        start = m.start(1)
        out.append(PIIFinding(start, start + len(name), "PERSON", "heuristic-ner", name))
    for m in _PAIR_RE.finditer(text):
        first, last = m.group(1), m.group(2)
        if first in FIRST_NAMES and last not in STOPWORDS:
            out.append(PIIFinding(m.start(), m.end(), "PERSON", "heuristic-ner", m.group(0)))
    return out


# --------------------------------------------------------------------------
# Layer 3: optional spaCy NER
# --------------------------------------------------------------------------


class SpacyNER:
    """Statistical NER. Raises ImportError/OSError if spaCy or the model is missing."""

    def __init__(self, model: str = "en_core_web_sm"):
        import spacy  # optional dependency

        self.model = model
        self._nlp = spacy.load(model)

    def findings(self, text: str) -> list[PIIFinding]:
        return [
            PIIFinding(ent.start_char, ent.end_char, "PERSON", "spacy-ner", ent.text)
            for ent in self._nlp(text).ents
            if ent.label_ == "PERSON" and _plausible_person(ent.text, text, ent.start_char)
        ]


_NAME_TOKEN_RE = re.compile(rf"^{_NAME}$")


def _plausible_person(span: str, text: str, start: int) -> bool:
    """Filter spaCy's PERSON guesses. The small model tags ops/prompt words as people
    ("Respond", "JSON", "Cordon", "lookup inventory-db"). Redacting those would corrupt
    the prompt template and strip evidence, so demand name-shaped tokens."""
    tokens = span.split()
    if not tokens or any(not _NAME_TOKEN_RE.match(t) or t in STOPWORDS for t in tokens):
        return False
    if len(tokens) == 1:
        # A lone capitalised word at a sentence start is usually just a capitalised word.
        before = text[:start].rstrip()
        if (not before or before[-1] in ".!?:\n") and tokens[0] not in FIRST_NAMES:
            return False
    return True


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------


def _merge(findings: Iterable[PIIFinding]) -> list[PIIFinding]:
    kept: list[PIIFinding] = []
    for f in sorted(findings, key=lambda f: (f.start, -(f.end - f.start))):
        if kept and f.start < kept[-1].end:
            continue  # overlaps an earlier/longer finding
        kept.append(f)
    return kept


class PIIDetector:
    MODES = ("off", "heuristic", "spacy")  # "off" = regex only; "spacy" = regex + heuristic + spaCy

    def __init__(self, ner: str = "heuristic", spacy_model: str = "en_core_web_sm"):
        if ner not in self.MODES:
            raise ValueError(f"PII NER mode must be one of {self.MODES}, got {ner!r}")
        self.use_heuristic = ner in ("heuristic", "spacy")
        self.spacy: SpacyNER | None = None
        if ner == "spacy":
            try:
                self.spacy = SpacyNER(spacy_model)
            except (ImportError, OSError) as exc:
                print(f"[pii] spaCy NER requested but unavailable ({type(exc).__name__}: {exc}); "
                      "continuing with regex + heuristic NER", file=sys.stderr)

    @property
    def name(self) -> str:
        layers = ["regex"]
        if self.use_heuristic:
            layers.append("heuristic-ner")
        if self.spacy is not None:
            layers.append(f"spacy:{self.spacy.model}")
        return "+".join(layers)

    def find(self, text: str) -> list[PIIFinding]:
        findings = regex_findings(text)
        if self.use_heuristic:
            findings += heuristic_name_findings(text)
        if self.spacy is not None:
            findings += self.spacy.findings(text)
        return _merge(findings)

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        redacted, findings = self.redact_with_findings(text)
        return redacted, count_by(findings, "label")

    def redact_with_findings(self, text: str) -> tuple[str, list[PIIFinding]]:
        findings = self.find(text)
        for f in reversed(findings):
            text = text[:f.start] + f"[REDACTED_{f.label}]" + text[f.end:]
        return text, findings


def count_by(findings: Iterable[PIIFinding], key: str) -> dict[str, int]:
    """key: 'label' -> {"PERSON": 2}; 'source' -> {"PERSON/spacy-ner": 1, "EMAIL/regex": 1}."""
    counts: dict[str, int] = {}
    for f in findings:
        k = f.label if key == "label" else f"{f.label}/{f.source}"
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items()))


def main() -> None:
    """Explain which layer caught what:  python -m guardrails "text" [--ner spacy]"""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m guardrails",
                                     description="Show every PII finding and the layer that detected it")
    parser.add_argument("text", nargs="?", help="text to scan (default: read stdin)")
    parser.add_argument("--ner", choices=PIIDetector.MODES, default="heuristic")
    args = parser.parse_args()
    text = args.text if args.text is not None else sys.stdin.read()
    detector = PIIDetector(args.ner)
    redacted, findings = detector.redact_with_findings(text)
    print(f"detector: {detector.name}\n")
    if not findings:
        print("no PII found")
    for f in findings:
        print(f"  {f.label:<7} {f.source:<14} {f.start:>4}-{f.end:<4} {f.text!r}")
    print(f"\nredacted: {redacted}")
