"""run.py — XORCISM connector for agentless Cloud AI Discovery (AI-SPM / Shadow AI).

Discovers AI/LLM services across cloud accounts (AWS Bedrock / SageMaker, Azure OpenAI / ML, GCP
Vertex AI) from the cloud control plane and normalizes each into an AISYSTEM record so XORCISM's AI
inventory reflects what is *actually* running — and flags ungoverned ones as Shadow AI.

Modes:
    offline : params["file"] -> a saved discovery export ({services:[...]} / aws/azure/gcp blocks).
    demo    : no config       -> the bundled sample.json.
(A live cloud pull would use the per-cloud read-only SDK calls; kept out of the worker sample so it
stays stdlib-only and credential-free.)

Normalized result: {aisystems:[{name, provider, model, modelType, hosting, endpoint, discovered,
discoverySource}]} -> runner.import_ai_systems (idempotent by name+provider). Worker-safe: stdlib
only, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

_PROVIDER = {"aws": "AWS", "bedrock": "AWS Bedrock", "sagemaker": "AWS SageMaker",
             "azure": "Azure OpenAI", "azureml": "Azure ML", "gcp": "GCP Vertex AI", "vertex": "GCP Vertex AI"}


def _rows(data: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        out: List[Dict[str, Any]] = []
        for k in keys + ("services", "models", "endpoints", "results", "data", "items"):
            v = data.get(k)
            if isinstance(v, list):
                out += [r for r in v if isinstance(r, dict)]
        return out
    return []


def _normalize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    systems: List[Dict[str, Any]] = []
    for r in rows:
        prov_key = str(r.get("provider") or r.get("cloud") or r.get("service") or "").lower()
        provider = _PROVIDER.get(prov_key, r.get("provider") or "Cloud")
        model = str(r.get("model") or r.get("modelId") or r.get("foundationModel") or r.get("name") or "model")
        name = str(r.get("name") or r.get("deploymentName") or r.get("endpointName") or f"{provider} {model}")
        systems.append({
            "name": name[:160],
            "provider": str(provider),
            "model": model,
            "modelType": str(r.get("modelType") or r.get("type") or "LLM"),
            "hosting": "SaaS" if "openai" in prov_key or "bedrock" in prov_key or "vertex" in prov_key else "Self-hosted",
            "endpoint": str(r.get("endpoint") or r.get("endpointUrl") or r.get("arn") or ""),
            "discovered": 1,
            "discoverySource": str(r.get("region") or prov_key or "cloud-ai-discovery"),
        })
    return {"aisystems": systems}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    rows = _rows(data, "services", "models", "endpoints")
    # also accept per-cloud blocks: {"bedrock":[...], "sagemaker":[...], "azure":[...], "vertex":[...]}
    if isinstance(data, dict):
        for k in ("bedrock", "sagemaker", "azure", "azureml", "vertex", "gcp"):
            for r in (data.get(k) or []):
                if isinstance(r, dict):
                    r.setdefault("provider", k)
                    rows.append(r)
    return _normalize(rows[:limit])


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
