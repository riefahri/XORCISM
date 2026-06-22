#!/usr/bin/env python3
"""
owasp-ai-threat-advisor — Agent Threat Advisor (OWASP AI Exchange, https://owaspai.org).

Given a short description of an AI / agentic system, prints the applicable AI threats with their
lifecycle phase, impact and mitigating controls. Worker-safe: no DB, no network, no target. The
catalogue mirrors server/aiexchange.ts (the in-app /ai-threat-advisor).

The worker passes parameters as a JSON object on stdin (or --params '<json>'). ASCII-only output.
"""
import json
import sys

# (ref, name, category, lifecycle, impact, description, controls, applies_to)
THREATS = [
    ("AIX-01", "Direct prompt injection", "Prompt injection", "Runtime/use", "High",
     "A user crafts input that overrides the model's instructions to bypass guardrails.",
     "Instruction/data separation, system-prompt hardening, output filtering, least-privilege tools, human approval.", ["llm", "agent"]),
    ("AIX-02", "Indirect prompt injection", "Prompt injection", "Runtime/use", "High",
     "Malicious instructions hidden in external content the model ingests.",
     "Treat retrieved content as untrusted, sanitization, provenance tagging, sandboxed tool output, dual-LLM pattern.", ["llm", "agent", "external"]),
    ("AIX-03", "Excessive agency", "Excessive agency", "Design/runtime", "High",
     "An agent has more capability/autonomy/permissions than its task needs, amplifying any compromise.",
     "Least-privilege tools/scopes, allow-list actions, human-in-the-loop for high impact, per-action authz.", ["agent", "autonomous", "tools"]),
    ("AIX-04", "Tool / function misuse", "Tool misuse", "Runtime", "High",
     "The agent is manipulated into invoking tools with attacker-controlled arguments.",
     "Strict tool schemas + validation, output encoding, scoped credentials, rate limits, confirmation for irreversible actions.", ["agent", "tools"]),
    ("AIX-05", "Memory / context poisoning", "Memory poisoning", "Runtime", "Medium",
     "Persistent memory or RAG store is poisoned to influence future decisions.",
     "Authenticate writes, provenance + integrity checks, segregate trusted/untrusted memory, expiry & review.", ["agent", "memory"]),
    ("AIX-06", "Goal / instruction manipulation", "Goal manipulation", "Runtime", "High",
     "An adversary redirects the agent's objective toward harmful goals.",
     "Immutable goal anchoring, plan validation, guardrail policies, goal-drift monitoring, human plan review.", ["agent", "autonomous"]),
    ("AIX-07", "Cascading / multi-agent failures", "Cascading failures", "Runtime", "High",
     "Errors/compromise in one agent propagate across a multi-agent system.",
     "Circuit breakers, isolation, inter-agent output validation, blast-radius limits, kill-switch.", ["agent", "autonomous"]),
    ("AIX-08", "Rogue / impersonated agent", "Identity & permissions", "Runtime", "High",
     "An unauthorized or spoofed agent joins the workflow or assumes another's identity.",
     "Strong agent identity (mTLS/signed), authn/authz between agents, trusted-agent registry, anomaly detection.", ["agent", "autonomous"]),
    ("AIX-09", "Identity & privilege abuse (NHI)", "Identity & permissions", "Runtime", "High",
     "The agent's non-human identity/tokens are abused for lateral movement or escalation.",
     "Short-lived scoped credentials, secret vaulting, per-tool identities, just-in-time access, monitor NHI usage.", ["agent", "autonomous", "tools"]),
    ("AIX-10", "Sensitive information disclosure", "Sensitive data disclosure", "Runtime/use", "High",
     "The model leaks training data, secrets, PII or context via its outputs.",
     "Data minimization, output DLP/redaction, no secrets in prompts, retrieval scoping, response review.", ["llm", "agent", "sensitive"]),
    ("AIX-11", "Insecure output handling", "Insecure output handling", "Runtime", "Medium",
     "Downstream systems trust and execute model output (XSS, SQLi, command injection).",
     "Treat output as untrusted, contextual encoding, sandbox generated code, validate before execution.", ["llm", "agent", "tools"]),
    ("AIX-12", "Training-data poisoning", "Data poisoning", "Development", "High",
     "Manipulated training/fine-tuning data introduces backdoors or bias.",
     "Data provenance & curation, anomaly detection, dataset signing, robust training, backdoor evaluation.", ["ml", "llm"]),
    ("AIX-13", "Model / IP theft", "Model theft", "Use/development", "Medium",
     "The model or weights are extracted via queries or exfiltrated from storage.",
     "Rate limiting, output watermarking, access control on weights, detect extraction patterns.", ["ml", "llm"]),
    ("AIX-14", "Evasion / adversarial examples", "Evasion", "Use", "Medium",
     "Crafted inputs cause misclassification at inference time.",
     "Adversarial training, input validation, ensembles, confidence thresholds + human review.", ["ml"]),
    ("AIX-15", "Supply-chain compromise (models/plugins)", "Supply chain", "Development", "High",
     "A poisoned base model, dataset, library or plugin introduces malicious behavior.",
     "AIBOM/SBOM, source verification, signed models/plugins, dependency scanning, plugin allow-listing.", ["ml", "llm", "agent", "tools"]),
    ("AIX-16", "Model DoS / unbounded consumption", "Denial of service", "Use", "Medium",
     "Expensive prompts, recursive loops or tool storms exhaust compute/budget.",
     "Rate/cost limits, loop/recursion caps, timeouts, budget guards, input-size limits.", ["llm", "agent", "autonomous"]),
    ("AIX-17", "Over-reliance / hallucination", "Hallucination & over-reliance", "Use", "Medium",
     "Users or automation act on confident but incorrect output.",
     "Cite sources, confidence signals, human review for consequential decisions, ground with retrieval.", ["llm", "agent"]),
]


def read_params():
    if "--params" in sys.argv:
        return json.loads(sys.argv[sys.argv.index("--params") + 1])
    data = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    return json.loads(data) if data else {}


def main():
    try:
        p = read_params()
    except Exception:
        p = {}
    shapes = set()
    st = str(p.get("system_type", "agent")).lower()
    if st in ("llm", "agent", "ml"):
        shapes.add(st)
    for key, shape in (("uses_tools", "tools"), ("has_memory", "memory"), ("autonomous", "autonomous"),
                       ("external_data", "external"), ("sensitive_data", "sensitive")):
        if p.get(key):
            shapes.add(shape)
    if not shapes:
        shapes.add("agent")

    def relevant(applies):
        return len(shapes.intersection(applies)) > 0

    impact_w = {"High": 3, "Medium": 2, "Low": 1}
    rows = [t for t in THREATS if relevant(t[7])]
    rows.sort(key=lambda t: (len(shapes.intersection(t[7])) * 2 + impact_w.get(t[4], 1)), reverse=True)

    print("OWASP AI Exchange - Agent Threat Advisor")
    print("Source: https://owaspai.org/")
    print("System shapes: " + ", ".join(sorted(shapes)))
    print("Applicable threats: %d (high impact: %d)" % (len(rows), sum(1 for t in rows if t[4] == "High")))
    print("=" * 72)
    for t in rows:
        ref, name, cat, life, impact, desc, ctrl, _ = t
        print("\n[%s] %s  (%s | %s | impact: %s)" % (ref, name, cat, life, impact))
        print("  Threat:   " + desc)
        print("  Controls: " + ctrl)
    print("\n" + "=" * 72)
    print("Done. Map these to your threat model (/ai-threat-advisor) and assign mitigating controls.")
    # machine-readable result for the runner / job summary
    print("RESULT_JSON=" + json.dumps({"applicable": len(rows), "high": sum(1 for t in rows if t[4] == "High"),
                                       "shapes": sorted(shapes), "threats": [t[0] for t in rows]}))


if __name__ == "__main__":
    main()
