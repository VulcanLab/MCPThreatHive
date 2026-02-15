"""
Baseline checker for MCP configurations.

Very lightweight rule engine:
- Loads baseline rules from config/mcp_baselines.yaml
- Each rule targets a target_type (e.g., server_config, tool_config)
- Supports simple checks: key existence and equality

Rule format (YAML):
baseline_rules:
  - id: server-timeout
    title: "Server timeout is configured"
    target_type: "server_config"
    field: "timeouts.request_timeout_seconds"
    operator: "exists"  # exists | eq
    expected: 30        # optional if operator=eq
    severity: "medium"
    description: "Set server request timeout to avoid resource exhaustion"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml


BASELINE_FILE = Path(__file__).parent.parent / "config" / "mcp_baselines.yaml"


def load_baseline_rules() -> List[Dict[str, Any]]:
    if not BASELINE_FILE.exists():
        return []
    try:
        data = yaml.safe_load(BASELINE_FILE.read_text(encoding="utf-8")) or {}
        return data.get("baseline_rules", [])
    except Exception:
        return []


def _get_by_path(data: Dict[str, Any], path: str):
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def check_baseline(config_data: Dict[str, Any], target_type: str = "server_config") -> Dict[str, Any]:
    rules = load_baseline_rules()
    findings = []
    passed = 0
    failed = 0

    for rule in rules:
        if rule.get("target_type") != target_type:
            continue
        operator = rule.get("operator", "exists")
        field = rule.get("field", "")
        expected = rule.get("expected")
        value = _get_by_path(config_data, field) if field else None

        # Support multiple operators
        is_pass = False
        if operator == "exists":
            is_pass = value is not None
        elif operator == "eq":
            is_pass = value == expected
        elif operator == "ne":
            is_pass = value != expected
        elif operator == "gt":
            is_pass = isinstance(value, (int, float)) and isinstance(expected, (int, float)) and value > expected
        elif operator == "gte":
            is_pass = isinstance(value, (int, float)) and isinstance(expected, (int, float)) and value >= expected
        elif operator == "lt":
            is_pass = isinstance(value, (int, float)) and isinstance(expected, (int, float)) and value < expected
        elif operator == "lte":
            is_pass = isinstance(value, (int, float)) and isinstance(expected, (int, float)) and value <= expected
        elif operator == "in":
            is_pass = value in (expected if isinstance(expected, list) else [expected])
        elif operator == "not_in":
            is_pass = value not in (expected if isinstance(expected, list) else [expected])
        elif operator == "regex":
            import re
            if isinstance(value, str) and isinstance(expected, str):
                is_pass = bool(re.search(expected, value, re.IGNORECASE))
        elif operator == "contains":
            if isinstance(value, str) and isinstance(expected, str):
                is_pass = expected.lower() in value.lower()
            elif isinstance(value, list):
                is_pass = expected in value
        elif operator == "not_empty":
            is_pass = value is not None and value != "" and value != [] and value != {}
        else:
            is_pass = False

        if is_pass:
            passed += 1
        else:
            failed += 1

        findings.append({
            "rule_id": rule.get("id"),
            "title": rule.get("title"),
            "passed": is_pass,
            "operator": operator,
            "field": field,
            "expected": expected,
            "actual": value,
            "severity": rule.get("severity", "medium"),
            "description": rule.get("description", "")
        })

    total = passed + failed
    score = (passed / total) * 100 if total > 0 else 100.0
    return {
        "baseline_version": "1.0.0",
        "passed_count": passed,
        "failed_count": failed,
        "score": score,
        "findings": findings
    }


def load_config_from_path(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    if p.suffix.lower() in [".json"]:
        return json.loads(p.read_text(encoding="utf-8"))
    if p.suffix.lower() in [".yaml", ".yml"]:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {}

