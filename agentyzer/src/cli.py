"""CLI for the Agentic Vulnerability Analyzer.

Submits assessment requests to the REST API and polls for results.

Usage examples::

    # Async (default) — submit, poll, print result
    agentyzer assess --component mylib --vuln CVE-2021-44228

    # Synchronous — block until result is ready
    agentyzer assess --component mylib --vuln CVE-2021-44228 --sync

    # Just check server health
    agentyzer health

    # List / inspect existing jobs
    agentyzer jobs
    agentyzer result <job-id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

DEFAULT_BASE_URL = "http://localhost:8000"
POLL_INTERVAL = 2  # seconds

DEBUG_LABELS = {
    "advisories": "advisory summary",
    "affected_ranges_count": "affected ranges",
    "affected_ranges_summary": "affected range summaries",
    "affected_versions_count": "explicit affected versions",
    "ast_context": "AST context",
    "component_cfg": "component config",
    "component_name": "component",
    "debug": "debug mode",
    "deep_analysis": "deep analysis",
    "dep_info": "resolved dependency info",
    "dependency_paths": "dependency path hints",
    "discovered_vulns": "discovered vulnerabilities",
    "llm_analysis": "LLM analysis",
    "locked_version": "locked version",
    "ollama": "LLM client",
    "repo_path": "repository path",
    "snippets": "code snippets",
    "structure": "code structure",
    "summary": "advisory summary text",
    "transitive_analysis": "transitive analysis",
    "usage": "code usage hits",
    "user_guidance": "analyst guidance",
    "vuln_id": "vulnerability id",
    "version_inventory": "version inventory",
    "what_if": "what-if remediation",
    "advisory_relevant": "advisory relevance",
}

DEBUG_ORDER = {
    "component_name": 10,
    "vuln_id": 20,
    "repo_path": 30,
    "locked_version": 40,
    "dep_info": 50,
    "advisories": 60,
    "summary": 70,
    "user_guidance": 80,
    "dependency_paths": 90,
    "usage": 100,
    "snippets": 110,
    "structure": 120,
    "ast_context": 130,
    "llm_analysis": 140,
    "deep_analysis": 150,
    "transitive_analysis": 160,
    "version_inventory": 170,
    "what_if": 175,
    "debug": 999,
}


# ===================================================================== #
# HTTP helpers                                                           #
# ===================================================================== #


def _client(
    base_url: str,
    *,
    token: str,
    owner: str,
) -> httpx.Client:
    headers = {"X-Agentyzer-Owner": owner}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=base_url, timeout=300, headers=headers)


def _service_token(args: argparse.Namespace) -> str:
    admin_scope = args.owner == "*"
    direct_setting = (
        "AGENTYZER_ADMIN_TOKEN" if admin_scope else "AGENTYZER_SERVICE_TOKEN"
    )
    direct = os.environ.get(direct_setting, "").strip()
    if direct:
        return direct
    token_file = str(
        args.admin_token_file if admin_scope else args.token_file
    ).strip()
    if token_file:
        return Path(token_file).read_text(encoding="utf-8").strip()
    return ""


def _command_client(args: argparse.Namespace) -> httpx.Client:
    return _client(
        args.url,
        token=_service_token(args),
        owner=args.owner,
    )


def _die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _print_json(data: dict | list) -> None:
    print(json.dumps(data, indent=2))


def _summarize_debug_dict(value: dict[str, Any]) -> str | None:
    if "version_table" in value or "worst_case" in value:
        table = value.get("version_table", [])
        worst = value.get("worst_case", {})
        return (
            f"{len(table)} version rows, "
            f"worst_case_affected={worst.get('affected', False)}"
        )
    if "current_version" in value and "remediation" in value:
        cur = value.get("current_version", "?")
        aff = value.get("current_affected", False)
        fixes = value.get("fixed_versions", [])
        return f"current={cur}, affected={aff}, fixed_versions={fixes}"
    if "reachable" in value and "reasoning" in value:
        parts = []
        if "reachable" in value:
            parts.append(f"reachable={value.get('reachable')}")
        if "confidence" in value:
            parts.append(f"confidence={value.get('confidence')}")
        if "confirmed" in value:
            parts.append(f"confirmed={value.get('confirmed')}")
        if "risk_level" in value:
            parts.append(f"risk_level={value.get('risk_level')}")
        return ", ".join(parts)
    if "found" in value and "locked_version" in value:
        return (
            f"found={value.get('found')}, "
            f"locked_version={value.get('locked_version')}, "
            f"direct={value.get('direct', False)}, "
            f"transitive={value.get('transitive', False)}"
        )
    return None


def _summarize_debug_list(value: list[Any]) -> str | None:
    if not value:
        return "0 items"
    if all(isinstance(item, dict) for item in value):
        keys = sorted({key for item in value for key in item.keys()})
        preview = ", ".join(keys[:4])
        suffix = "..." if len(keys) > 4 else ""
        return f"{len(value)} items ({preview}{suffix})"
    if all(isinstance(item, str) for item in value):
        preview = ", ".join(value[:3])
        suffix = ", ..." if len(value) > 3 else ""
        return f"{len(value)} items: {preview}{suffix}"
    return f"{len(value)} items"


def _format_debug_value(value: Any) -> str:
    if isinstance(value, dict):
        summarized = _summarize_debug_dict(value)
        if summarized is not None:
            return summarized
        return json.dumps(value, sort_keys=True)
    if isinstance(value, list):
        summarized = _summarize_debug_list(value)
        if summarized is not None:
            return summarized
        return json.dumps(value, sort_keys=True)
    return str(value)


def _debug_label(key: str) -> str:
    return DEBUG_LABELS.get(key, key.replace("_", " "))


def _sorted_debug_items(mapping: dict[str, Any]) -> list[tuple[str, Any]]:
    return sorted(
        mapping.items(),
        key=lambda item: (DEBUG_ORDER.get(item[0], 500), _debug_label(item[0])),
    )


def _print_debug_mapping(
    title: str, mapping: dict[str, Any], indent: str = "      "
) -> None:
    if not mapping:
        return
    print(f"{indent}{title}:")
    for key, value in _sorted_debug_items(mapping):
        label = _debug_label(key)
        if isinstance(value, dict):
            summarized = _summarize_debug_dict(value)
            if summarized is not None:
                print(f"{indent}  {label}: {summarized}")
                continue
            print(f"{indent}  {label}:")
            for nested_key, nested_value in _sorted_debug_items(value):
                print(
                    f"{indent}    {_debug_label(nested_key)}: {_format_debug_value(nested_value)}"
                )
            continue
        if isinstance(value, list):
            summarized = _summarize_debug_list(value)
            if summarized is not None:
                print(f"{indent}  {label}: {summarized}")
                continue
            print(f"{indent}  {label}:")
            for item in value:
                print(f"{indent}    - {_format_debug_value(item)}")
            continue
        print(f"{indent}  {label}: {_format_debug_value(value)}")


# ===================================================================== #
# Commands                                                               #
# ===================================================================== #


def cmd_health(args: argparse.Namespace) -> None:
    with _command_client(args) as c:
        r = c.get("/health")
        r.raise_for_status()
        _print_json(r.json())


def cmd_assess(args: argparse.Namespace) -> None:
    payload: dict = {"component_name": args.component}
    if args.vuln:
        payload["vuln_id"] = args.vuln
    if args.cvss_vector:
        payload["cvss_vector"] = args.cvss_vector
    if args.focus_path:
        payload["focus_path"] = args.focus_path
    if args.guidance:
        payload["user_guidance"] = args.guidance
    if args.debug:
        payload["debug"] = True

    with _command_client(args) as c:
        r = c.post("/assess", json=payload, params={"sync": args.sync})
        r.raise_for_status()
        data = r.json()

        if args.sync:
            _print_assessment(data)
            return

        # Async mode — we got a job ID back.
        job_id = data["job_id"]
        print(f"Job submitted: {job_id}", file=sys.stderr)
        print(f"Polling {data['poll_url']} ...", file=sys.stderr)

        _poll_until_done(c, job_id)


def _poll_until_done(c: httpx.Client, job_id: str) -> None:
    while True:
        time.sleep(POLL_INTERVAL)
        r = c.get(f"/jobs/{job_id}")
        r.raise_for_status()
        status = r.json()

        state = status["status"]
        print(f"  status: {state}", file=sys.stderr)

        if state == "completed":
            r2 = c.get(f"/jobs/{job_id}/result")
            r2.raise_for_status()
            _print_assessment(r2.json())
            return
        if state == "failed":
            _die(f"Job failed: {status.get('error', 'unknown error')}")


def cmd_jobs(args: argparse.Namespace) -> None:
    with _command_client(args) as c:
        r = c.get("/jobs")
        r.raise_for_status()
        data = r.json()

        jobs = data.get("jobs", [])
        if not jobs:
            print("No jobs.")
            return

        for j in jobs:
            finished = j.get("finished_at") or ""
            err = f"  error={j['error']}" if j.get("error") else ""
            print(
                f"  {j['job_id']}  {j['status']:<10}  created={j['created_at']}  finished={finished}{err}"
            )


def cmd_result(args: argparse.Namespace) -> None:
    with _command_client(args) as c:
        r = c.get(f"/jobs/{args.job_id}/result")
        if r.status_code == 409:
            detail = r.json().get("detail", "")
            _die(f"Job not ready: {detail}")
        r.raise_for_status()
        _print_assessment(r.json())


def cmd_delete(args: argparse.Namespace) -> None:
    with _command_client(args) as c:
        r = c.delete(f"/jobs/{args.job_id}")
        if r.status_code == 409:
            _die(r.json().get("detail", "Cannot delete"))
        r.raise_for_status()
        print(f"Job {args.job_id} deleted.")


# ===================================================================== #
# Output formatting                                                     #
# ===================================================================== #


def _print_assessment(data: dict) -> None:
    a = data.get("assessment", {})

    verdict = a.get("verdict", "?")
    confidence = a.get("confidence", "?")
    affected = a.get("affected", False)
    exposure = a.get("exposure", "?")

    # Header
    icon = "\u2717" if affected else "\u2713"
    color_start = "\033[91m" if affected else "\033[92m"
    color_end = "\033[0m"
    print(
        f"\n{color_start}{icon} {verdict}{color_end}  (confidence: {confidence}, exposure: {exposure})"
    )

    advisory_relevance = a.get("advisory_relevance")
    if advisory_relevance:
        decision = (
            "relevant" if advisory_relevance.get("relevant", True) else "filtered out"
        )
        source = advisory_relevance.get("source", "rules")
        print(f"  Advisory filter: {decision} ({source})")
        for reason in advisory_relevance.get("reasons", [])[:2]:
            print(f"    • {reason}")

    version_analysis = a.get("version_analysis") or {}
    if version_analysis.get("detected_version"):
        src = version_analysis.get("version_source", "unknown")
        affected_label = (
            "affected" if version_analysis.get("affected") else "not affected"
        )
        print(
            f"  Version analysis: {version_analysis['detected_version']} ({src}, {affected_label})"
        )
        note = version_analysis.get("note")
        if note:
            print(f"    • {note}")
    checked_versions = version_analysis.get("checked_versions", [])
    if checked_versions:
        print("    Project versions analyzed:")
        for item in checked_versions:
            ref = item.get("ref") or "?"
            ref_type = item.get("ref_type") or "?"
            version = item.get("version") or "-"
            status = "AFFECTED" if item.get("affected") else "not affected"
            source = item.get("source")
            notes = item.get("notes") or ""
            detail = f" [{source}]" if source else ""
            if notes:
                detail += f" ({notes})"
            print(f"      - {ref} ({ref_type}): {version} — {status}{detail}")

    # CVSS
    cvss = a.get("adjusted_cvss")
    if cvss:
        orig = cvss.get("original_score", "?")
        adj = cvss.get("adjusted_score", "?")
        ver = cvss.get("version", "?")
        print(f"  CVSS {ver}: {orig} → {adj}")
        for reason in cvss.get("reasons", []):
            print(f"    • {reason}")
        vctx = cvss.get("version_context", {})
        if vctx.get("detected_version"):
            src = vctx.get("version_source", "unknown")
            ranges = vctx.get("affected_ranges_summary", [])
            range_hint = f"  [{ranges[0]}]" if ranges else ""
            print(
                f"    ↳ detected version: {vctx['detected_version']} ({src}){range_hint}"
            )
            if len(ranges) > 1:
                for extra_range in ranges[1:]:
                    print(f"      range: {extra_range}")
            inputs = vctx.get("comparison_inputs", {})
            if inputs:
                _print_debug_mapping("version debug inputs", inputs)
            trace = vctx.get("comparison_trace", [])
            if trace:
                print("      trace:")
                for line in trace:
                    print(f"        - {line}")

    # Summary
    summary = a.get("summary", "")
    if summary:
        print(f"\n  {summary}")

    # Reasoning
    reasoning = a.get("reasoning", "")
    if reasoning:
        print(f"\n  Reasoning: {reasoning}")

    for label, key in (
        ("Researcher view", "researcher_view"),
        ("Remediation view", "remediation_view"),
        ("Audit view", "audit_view"),
    ):
        view = a.get(key) or {}
        if not view:
            continue
        print(f"\n  {label}:")
        objective = view.get("objective")
        if objective:
            print(f"    objective: {objective}")
        summary = view.get("summary") or view.get("conclusion")
        if summary:
            print(f"    summary: {summary}")
        for item in view.get("findings", [])[:3]:
            print(f"    - {item}")
        for item in view.get("recommendations", [])[:3]:
            print(f"    - {item}")
        status = view.get("status")
        if status:
            print(f"    status: {status}")
        consistency = view.get("consistency")
        if consistency:
            print(f"    consistency: {consistency}")
        if view.get("downgrade_target"):
            supported = "yes" if view.get("downgrade_supported") else "no"
            print(f"    downgrade supported: {supported}")
        for item in view.get("checks", [])[:3]:
            print(f"    - {item}")

    # Steps
    steps = data.get("steps", [])
    if steps:
        print(f"\n  Pipeline steps ({len(steps)}):")
        for s in steps:
            status_icon = {"pass": "\u2713", "fail": "\u2717", "skip": "-"}.get(
                s.get("status", ""), "?"
            )
            print(f"    {status_icon} {s.get('title', s.get('step', '?'))}")
            inputs = s.get("findings", {}).get("inputs")
            if inputs:
                _print_debug_mapping("node inputs", inputs)
            for ev in s.get("evidence", [])[:3]:
                print(f"      {ev}")

    print()


# ===================================================================== #
# Argument parser                                                       #
# ===================================================================== #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentyzer",
        description="CLI for the Agentic Vulnerability Analyzer",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the API server (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("AGENTYZER_SERVICE_TOKEN_FILE", ""),
        help="File containing the Agentyzer service token",
    )
    parser.add_argument(
        "--admin-token-file",
        default=os.environ.get("AGENTYZER_ADMIN_TOKEN_FILE", ""),
        help="File containing the admin token used with --owner '*'",
    )
    parser.add_argument(
        "--owner",
        default=os.environ.get("AGENTYZER_CALLER_OWNER", "cli"),
        help="Owner identity used to isolate jobs (default: cli)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # health
    sub.add_parser("health", help="Check API server health")

    # assess
    p_assess = sub.add_parser("assess", help="Submit a vulnerability assessment")
    p_assess.add_argument("-c", "--component", required=True, help="Component name")
    p_assess.add_argument(
        "-v", "--vuln", default=None, help="Vulnerability ID (e.g. CVE-2021-44228)"
    )
    p_assess.add_argument(
        "--cvss-vector", default=None, help="CVSS vector string to rescore"
    )
    p_assess.add_argument(
        "--focus-path", default=None, help="Narrow code scan to this path"
    )
    p_assess.add_argument(
        "--guidance",
        default=None,
        metavar="TEXT",
        help="Additional analyst context passed to every LLM call "
        "(e.g. deployment environment, known mitigations)",
    )
    p_assess.add_argument(
        "--sync", action="store_true", help="Block until result is ready (no polling)"
    )
    p_assess.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output, including per-step inputs and full version comparison traces",
    )

    # jobs
    sub.add_parser("jobs", help="List all jobs")

    # result
    p_result = sub.add_parser("result", help="Fetch result of a completed job")
    p_result.add_argument("job_id", help="Job ID")

    # delete
    p_delete = sub.add_parser(
        "delete",
        help="Cancel a running job or delete a finished job",
    )
    p_delete.add_argument("job_id", help="Job ID")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "health": cmd_health,
        "assess": cmd_assess,
        "jobs": cmd_jobs,
        "result": cmd_result,
        "delete": cmd_delete,
    }

    try:
        dispatch[args.command](args)
    except httpx.ConnectError:
        _die(f"Cannot connect to {args.url} — is the server running?")
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            detail = exc.response.text
        _die(f"HTTP {exc.response.status_code}: {detail}")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
