"""Guardrail middleware: input, output, and PII.

* **Input**  scans untrusted text (incident titles, telemetry, log lines --
  anything an attacker could plant in a ticket or a log) for prompt-injection
  patterns *before* it reaches an LLM.
* **Output** scans commands the planner drafted *before* they reach a tool:
  only allow-listed binaries, and no shell metacharacters or chaining.
* **PII**    masks personal data and secrets so they are never sent to a model
  provider or written to the audit log. Regex rules handle fixed shapes
  (emails, IPs, phones, cards, keys). NER handles person names: a built-in
  heuristic detector, plus optional spaCy. See ``pii_detector.py``.

Injection and shell checks are deterministic pattern matching: a cheap first
line of defence that can be explained in an audit. They are not a replacement
for a classifier model, and ADR-02 says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .pii_detector import PIIDetector, count_by


class GuardrailViolation(Exception):
    def __init__(self, stage: str, reasons: list[str]):
        super().__init__(f"{stage} guardrail blocked: {'; '.join(reasons)}")
        self.stage = stage
        self.reasons = reasons


@dataclass
class GuardrailResult:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    sanitized_text: str = ""


INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction override", re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)", re.I)),
    ("role hijack", re.compile(r"\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(admin|root|developer|system)\b", re.I)),
    ("system prompt exfiltration", re.compile(r"\b(reveal|print|show|repeat)\s+(me\s+)?(your|the)\s+(system\s+prompt|hidden\s+instructions)", re.I)),
    ("fake role delimiter", re.compile(r"<\s*/?\s*(system|assistant)\s*>|\[\s*(system|INST)\s*\]", re.I)),
    ("tool coercion", re.compile(r"\b(run|execute|call)\s+(the\s+)?(following|this)\s+(command|tool)\b", re.I)),
]

ALLOWED_BINARIES = ("kubectl",)

SHELL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("command chaining (;)", re.compile(r";")),
    ("conditional chaining (&& / ||)", re.compile(r"&&|\|\|")),
    ("pipe", re.compile(r"\|")),
    ("backtick substitution", re.compile(r"`")),
    ("subshell $( )", re.compile(r"\$\(")),
    ("variable expansion ${ }", re.compile(r"\$\{")),
    ("redirection", re.compile(r"[<>]")),
    ("recursive delete", re.compile(r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r", re.I)),
    ("namespace deletion", re.compile(r"\bdelete\s+(ns|namespace)\b", re.I)),
    ("newline injection", re.compile(r"[\r\n]")),
    # --- privilege escalation (FR4) ---
    ("privilege escalation (sudo/su/doas)", re.compile(r"(?<![\w-])(sudo|su|doas)(?![\w-])", re.I)),
    ("chmod setuid / world-writable", re.compile(
        r"\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwxXt]*s|[2467][0-7]{3}\b|[0-7]{0,2}[0-7]{1,2}7\b)", re.I)),
    ("chown to root", re.compile(r"\bchown\s+(?:-\w+\s+)*root\b", re.I)),
    ("kubectl impersonation (--as)", re.compile(r"--as(?:-group|-uid)?[=\s]", re.I)),
    ("cluster-admin binding", re.compile(r"\bclusterrolebindings?\b|\bcluster-admin\b", re.I)),
    ("privileged container", re.compile(r"--privileged\b|\bprivileged\s*:\s*true\b", re.I)),
    ("host namespace access", re.compile(r"\bhost(?:PID|Network|IPC)\b", re.I)),
    # `exec` as the subcommand (only global flags such as `-n prod` may precede it).
    ("kubectl exec into a container", re.compile(r"\bkubectl\s+(?:-{1,2}\S+(?:\s+[^-\s]\S*)?\s+)*exec(?![\w-])", re.I)),
]

# A bare Kubernetes (DNS-1123) name can't execute anything, so a namespace or workload that is
# literally called "su" or "sudo" is not privilege escalation. Only check_argument uses this.
DNS1123_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_PRIV_WORD_LABEL = "privilege escalation (sudo/su/doas)"

# Multi-line recovery-script drafts (YAML/HCL) legitimately contain newlines;
# every other shell/privilege rule still applies to them.
_SCRIPT_EXEMPT_LABELS = frozenset({"newline injection"})

class GuardrailMiddleware:
    def __init__(self, pii_ner: str = "heuristic"):
        self.pii = PIIDetector(pii_ner)

    def check_input(self, text: str) -> GuardrailResult:
        reasons = [label for label, pattern in INJECTION_PATTERNS if pattern.search(text)]
        return GuardrailResult(allowed=not reasons, reasons=reasons, sanitized_text=text)

    def check_output(self, command: str) -> GuardrailResult:
        reasons: list[str] = []
        stripped = command.strip()
        binary = stripped.split(" ", 1)[0] if stripped else ""
        if binary not in ALLOWED_BINARIES:
            reasons.append(f"binary '{binary}' not in allow-list {ALLOWED_BINARIES}")
        reasons.extend(label for label, pattern in SHELL_PATTERNS if pattern.search(command))
        return GuardrailResult(allowed=not reasons, reasons=reasons, sanitized_text=command)

    def check_script(self, script: str) -> GuardrailResult:
        """Recovery-script drafts: shell metacharacters and privilege escalation, but multi-line is fine."""
        reasons = [label for label, pattern in SHELL_PATTERNS
                   if label not in _SCRIPT_EXEMPT_LABELS and pattern.search(script)]
        return GuardrailResult(allowed=not reasons, reasons=reasons, sanitized_text=script)

    def check_argument(self, value: str) -> GuardrailResult:
        """Tool arguments are identifiers, never shell fragments."""
        clean_name = len(value) <= 63 and DNS1123_NAME_RE.match(value) is not None
        reasons = [label for label, pattern in SHELL_PATTERNS
                   if not (clean_name and label == _PRIV_WORD_LABEL) and pattern.search(value)]
        return GuardrailResult(allowed=not reasons, reasons=reasons, sanitized_text=value)

    def redact_pii(self, text: str) -> tuple[str, dict[str, int]]:
        """Regex + NER redaction; see ``pii_detector.py`` for the layers."""
        return self.pii.redact(text)

    def redact_pii_detailed(self, text: str) -> tuple[str, dict[str, int], dict[str, int]]:
        """Like redact_pii, plus counts per detecting layer ("PERSON/spacy-ner": 1)."""
        redacted, findings = self.pii.redact_with_findings(text)
        return redacted, count_by(findings, "label"), count_by(findings, "source")

    def redact_text(self, text: str) -> str:
        return self.pii.redact(text)[0]
