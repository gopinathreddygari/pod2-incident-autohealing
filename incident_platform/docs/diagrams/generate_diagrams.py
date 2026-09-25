"""Regenerate both .excalidraw diagrams (standard library only).

    python docs/diagrams/generate_diagrams.py

Open the output at https://excalidraw.com (menu -> Open) or with the VS Code
Excalidraw extension. IDs and seeds are deterministic, so regenerating
without changes produces an identical file (clean git diffs).
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent

# Palette
INK = "#1e1e1e"
BLUE, BLUE_BG = "#1971c2", "#d0ebff"
GREEN, GREEN_BG = "#2f9e44", "#d3f9d8"
ORANGE, ORANGE_BG = "#e8590c", "#ffe8cc"
RED, RED_BG = "#e03131", "#ffe3e3"
VIOLET, VIOLET_BG = "#6741d9", "#e5dbff"
GREY, GREY_BG = "#495057", "#f1f3f5"


class Scene:
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.elements: list[dict] = []
        self._n = 0
        self._by_id: dict[str, dict] = {}

    def _id(self) -> str:
        self._n += 1
        return f"{self.prefix}-{self._n:03d}"

    def _base(self, kind: str, x: float, y: float, w: float, h: float, stroke: str = INK,
              bg: str = "transparent", style: str = "solid", sw: int = 2, rounded: bool = True) -> dict:
        eid = self._id()
        el = {
            "id": eid, "type": kind, "x": x, "y": y, "width": w, "height": h, "angle": 0,
            "strokeColor": stroke, "backgroundColor": bg, "fillStyle": "solid", "strokeWidth": sw,
            "strokeStyle": style, "roughness": 1, "opacity": 100, "groupIds": [], "frameId": None,
            "roundness": {"type": 3} if rounded else None, "seed": 1000 + self._n,
            "version": 1, "versionNonce": 5000 + self._n, "isDeleted": False, "boundElements": [],
            "updated": 1, "link": None, "locked": False,
        }
        self.elements.append(el)
        self._by_id[eid] = el
        return el

    def text(self, x: float, y: float, text: str, size: int = 16, color: str = INK,
             container: str | None = None, align: str = "center") -> dict:
        lines = text.split("\n")
        w = max(len(line) for line in lines) * size * 0.55
        h = len(lines) * size * 1.25
        el = self._base("text", x, y, w, h, stroke=color, rounded=False)
        el.update({
            "text": text, "originalText": text, "fontSize": size, "fontFamily": 1,
            "textAlign": align, "verticalAlign": "middle" if container else "top",
            "containerId": container, "autoResize": True, "lineHeight": 1.25,
        })
        if container:
            c = self._by_id[container]
            el["x"] = c["x"] + (c["width"] - w) / 2
            el["y"] = c["y"] + (c["height"] - h) / 2
            c["boundElements"].append({"type": "text", "id": el["id"]})
        return el

    def box(self, x: float, y: float, w: float, h: float, label: str, stroke: str = INK,
            bg: str = "transparent", size: int = 16, style: str = "solid") -> dict:
        el = self._base("rectangle", x, y, w, h, stroke=stroke, bg=bg, style=style)
        self.text(0, 0, label, size=size, container=el["id"])
        return el

    def zone(self, x: float, y: float, w: float, h: float, title: str, stroke: str) -> dict:
        el = self._base("rectangle", x, y, w, h, stroke=stroke, style="dashed", sw=1)
        self.text(x + 12, y + 8, title, size=18, color=stroke, align="left")
        return el

    def line(self, x1: float, y1: float, x2: float, y2: float, stroke: str = GREY, style: str = "dashed") -> dict:
        el = self._base("line", x1, y1, abs(x2 - x1), abs(y2 - y1), stroke=stroke, style=style, sw=1, rounded=False)
        el.update({"points": [[0, 0], [x2 - x1, y2 - y1]], "lastCommittedPoint": None,
                   "startBinding": None, "endBinding": None, "startArrowhead": None, "endArrowhead": None})
        return el

    def arrow(self, x1: float, y1: float, x2: float, y2: float, label: str | None = None,
              start: dict | None = None, end: dict | None = None, stroke: str = INK,
              style: str = "solid", size: int = 14) -> dict:
        el = self._base("arrow", x1, y1, abs(x2 - x1), abs(y2 - y1), stroke=stroke, style=style, rounded=False)
        el["roundness"] = {"type": 2}
        el.update({
            "points": [[0, 0], [x2 - x1, y2 - y1]], "lastCommittedPoint": None,
            "startBinding": {"elementId": start["id"], "focus": 0, "gap": 4} if start else None,
            "endBinding": {"elementId": end["id"], "focus": 0, "gap": 4} if end else None,
            "startArrowhead": None, "endArrowhead": "arrow", "elbowed": False,
        })
        for shape in (start, end):
            if shape is not None:
                shape["boundElements"].append({"type": "arrow", "id": el["id"]})
        if label:
            t = self.text(0, 0, label, size=size, color=stroke)
            t["containerId"] = el["id"]
            t["verticalAlign"] = "middle"
            t["x"] = (x1 + x2) / 2 - t["width"] / 2
            t["y"] = (y1 + y2) / 2 - t["height"] / 2
            el["boundElements"].append({"type": "text", "id": t["id"]})
        return el

    def connect(self, a: dict, b: dict, label: str | None = None, **kw) -> dict:
        """Arrow between the facing edges of two boxes."""
        ax, ay, aw, ah = a["x"], a["y"], a["width"], a["height"]
        bx, by, bw, bh = b["x"], b["y"], b["width"], b["height"]
        if bx >= ax + aw:        # b is to the right
            p1, p2 = (ax + aw, ay + ah / 2), (bx, by + bh / 2)
        elif bx + bw <= ax:      # b is to the left
            p1, p2 = (ax, ay + ah / 2), (bx + bw, by + bh / 2)
        elif by >= ay + ah:      # b is below
            p1, p2 = (ax + aw / 2, ay + ah), (bx + bw / 2, by)
        else:                    # b is above
            p1, p2 = (ax + aw / 2, ay), (bx + bw / 2, by + bh)
        return self.arrow(*p1, *p2, label=label, start=a, end=b, **kw)

    def document(self) -> dict:
        return {
            "type": "excalidraw", "version": 2, "source": "incident_platform/docs/diagrams/generate_diagrams.py",
            "elements": self.elements,
            "appState": {"viewBackgroundColor": "#ffffff", "gridSize": None},
            "files": {},
        }


def system_architecture() -> dict:
    s = Scene("arch")
    s.text(40, 10, "Pod 2 -- Incident Remediation & Auto-Healing: System Architecture", size=28, align="left")

    # External inputs
    alerts = s.box(40, 110, 220, 90, "Alert sources\nPrometheus / Datadog\n/ tickets", GREY, GREY_BG)

    # Runtime zone
    s.zone(300, 70, 1000, 560, "Runtime -- incident_platform (in-process)", BLUE)
    orch = s.box(340, 120, 260, 80, "IncidentOrchestrator\n(hierarchical coordinator)", BLUE, BLUE_BG)
    store = s.box(660, 120, 260, 80, "IncidentStateStore\nstate machine", BLUE, BLUE_BG)
    triage = s.box(340, 260, 200, 70, "TriageAgent", BLUE, BLUE_BG)
    planner = s.box(580, 260, 240, 70, "RemediationPlannerAgent", BLUE, BLUE_BG)
    execv = s.box(860, 260, 260, 70, "ExecutionVerificationAgent", BLUE, BLUE_BG)
    think = s.box(340, 400, 420, 100,
                  "BaseAgent.think()\nPII redact -> input guard -> cache L1/L2\n-> router -> backend -> profiler -> audit",
                  VIOLET, VIOLET_BG, size=15)
    mcp = s.box(860, 400, 400, 100,
                "MCPToolServer  list_tools / call_tool\nschema -> arg guardrail -> circuit breaker\n9 tools across 5 risk classes",
                ORANGE, ORANGE_BG, size=15)
    llm = s.box(340, 540, 420, 70, "LLM backend: Mock (default)\nor OpenAI via ResilientBackend", VIOLET, VIOLET_BG, size=15)

    # Governance zone
    s.zone(1340, 70, 300, 560, "Security & Governance", RED)
    hitl = s.box(1370, 240, 240, 90, "HITLGate\ngated risk class OR\nconfidence < 0.75", RED, RED_BG)
    channel = s.box(1370, 380, 240, 80, "Approval channel\nSlack / PagerDuty / Console", RED, RED_BG, size=15)
    guard = s.box(1370, 120, 240, 80, "GuardrailMiddleware\ninjection / shell / PII", RED, RED_BG, size=15)
    sre = s.box(1370, 510, 240, 70, "On-call SRE", RED, "#ffffff")

    # External systems
    s.zone(860, 680, 440, 150, "External systems (mocked; clear seam)", GREY)
    k8s = s.box(890, 730, 380, 70, "Kubernetes API / Prometheus / Terraform", GREY, GREY_BG, size=15)

    # Observability
    s.zone(40, 680, 780, 150, "Observability (cross-cutting, injected)", GREEN)
    s.box(70, 730, 220, 70, "Tracer\nOTel-shaped spans", GREEN, GREEN_BG, size=15)
    s.box(320, 730, 220, 70, "AuditLog\nhash-chained JSONL", GREEN, GREEN_BG, size=15)
    s.box(570, 730, 220, 70, "Metrics\nlatency / tokens /\ncache / tool failures", GREEN, GREEN_BG, size=14)

    s.connect(alerts, orch, "incident")
    s.connect(orch, store, "transition()")
    s.connect(orch, triage)
    s.arrow(470, 200, 700, 260, start=orch, end=planner)
    s.arrow(560, 200, 990, 260, start=orch, end=execv)
    s.connect(triage, think)
    s.arrow(700, 330, 650, 400, start=planner, end=think)
    s.connect(think, llm)
    s.arrow(440, 330, 900, 400, "read-only tools", start=triage, end=mcp, stroke=ORANGE)
    s.connect(execv, mcp, "call_tool")
    s.connect(execv, hitl, "gate")
    s.connect(hitl, channel, "payload")
    s.connect(channel, sre)
    s.connect(mcp, k8s, "transport seam", stroke=GREY, style="dashed")
    s.arrow(1260, 420, 1370, 170, start=mcp, end=guard, stroke=RED, style="dashed")
    return s.document()


def agent_workflow_sequence() -> dict:
    s = Scene("seq")
    s.text(40, 10, "Agent Workflow Sequence -- with HITL approval boundary", size=28, align="left")

    lanes = [
        ("Orchestrator", BLUE, BLUE_BG), ("TriageAgent", BLUE, BLUE_BG), ("MCPToolServer", ORANGE, ORANGE_BG),
        ("think() / LLM", VIOLET, VIOLET_BG), ("PlannerAgent", BLUE, BLUE_BG), ("HITLGate", RED, RED_BG),
        ("On-call SRE", RED, "#ffffff"), ("ExecVerifyAgent", BLUE, BLUE_BG),
    ]
    x0, gap, top, bottom = 40, 190, 80, 1180
    centers = {}
    for i, (name, stroke, bg) in enumerate(lanes):
        x = x0 + i * gap
        head = s.box(x, top, 160, 50, name, stroke, bg, size=15)
        cx = x + 80
        centers[name] = cx
        s.line(cx, top + 50, cx, bottom)

    y = 170

    def msg(src: str, dst: str, label: str, color: str = INK, dashed: bool = False) -> None:
        nonlocal y
        # Labels sit above the arrow as free text: most messages are longer than
        # the gap between adjacent lifelines, and a bound label would hide its arrow.
        s.arrow(centers[src], y, centers[dst], y, stroke=color, style="dashed" if dashed else "solid")
        s.text(min(centers[src], centers[dst]) + 8, y - 20, label, size=13, color=color, align="left")
        y += 55

    def note(text: str, color: str = GREY) -> None:
        nonlocal y
        s.text(centers["Orchestrator"] - 60, y - 15, text, size=13, color=color, align="left")
        y += 35

    msg("Orchestrator", "TriageAgent", "RECEIVED -> TRIAGING: run(incident)")
    msg("TriageAgent", "MCPToolServer", "fetch_k8s_logs / correlate_telemetry (read-only, retried)", ORANGE)
    msg("MCPToolServer", "TriageAgent", "result | isError: circuit_open -> degraded", ORANGE, dashed=True)
    msg("TriageAgent", "think() / LLM", "evidence prompt + content cache_key", VIOLET)
    msg("think() / LLM", "TriageAgent", "root_cause, confidence, category  (cache hit = 0 tokens)", VIOLET, dashed=True)
    msg("TriageAgent", "Orchestrator", "TriageResult  (degraded -> ESCALATED)", dashed=True)
    msg("Orchestrator", "PlannerAgent", "TRIAGING -> PLANNING: run(incident, triage)")
    msg("PlannerAgent", "think() / LLM", "choose one action from list_tools()", VIOLET)
    msg("think() / LLM", "PlannerAgent", "action + steps", VIOLET, dashed=True)
    msg("PlannerAgent", "Orchestrator", "plan: code-bound args, kubectl command + IaC draft, both guardrail-checked", dashed=True)
    msg("Orchestrator", "ExecVerifyAgent", "run(incident, triage, plan)")

    boundary_top = y - 20
    msg("ExecVerifyAgent", "HITLGate", "evaluate(risk_class, confidence)", RED)
    s.text(centers["HITLGate"] - 70, y - 10, "PLANNING -> AWAITING_APPROVAL\n(incident paused)", size=13, color=RED, align="left")
    y += 50
    msg("HITLGate", "On-call SRE", "approval payload (Slack / PagerDuty)", RED)
    msg("On-call SRE", "HITLGate", "approve / reject", RED, dashed=True)
    msg("HITLGate", "ExecVerifyAgent", "APPROVED (resume) | REJECTED (stop)", RED, dashed=True)
    boundary_bottom = y - 20
    s._base("rectangle", centers["HITLGate"] - 120, boundary_top, centers["On-call SRE"] - centers["HITLGate"] + 330,
            boundary_bottom - boundary_top, stroke=RED, style="dashed", sw=2)
    s.text(centers["PlannerAgent"] - 75, boundary_top + 6, "HITL approval boundary\n(gated risk class OR\nconfidence < 0.75)",
           size=14, color=RED, align="left")

    msg("ExecVerifyAgent", "MCPToolServer", "EXECUTING: call_tool(action)  breaker + guardrail + audit", ORANGE)
    msg("MCPToolServer", "ExecVerifyAgent", "result", ORANGE, dashed=True)
    msg("ExecVerifyAgent", "MCPToolServer", "correlate_telemetry (post-remediation health)", ORANGE)
    msg("MCPToolServer", "ExecVerifyAgent", "healthy? -> VERIFIED | FAILED", ORANGE, dashed=True)
    msg("ExecVerifyAgent", "Orchestrator", "final state", dashed=True)
    note("Every arrow: tracer span + hash-chained audit entry. Every think(): cache checked before any token is spent.")
    return s.document()


def main() -> None:
    for name, builder in (("system_architecture", system_architecture),
                          ("agent_workflow_sequence", agent_workflow_sequence)):
        path = OUT_DIR / f"{name}.excalidraw"
        path.write_text(json.dumps(builder(), indent=2), encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
