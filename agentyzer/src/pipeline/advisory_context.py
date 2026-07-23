"""Prompt-bound advisory context and repository manifest discovery."""

from __future__ import annotations

import os

from src.agents import web_fetcher
from src.pipeline.state import PipelineState


MAX_ADVISORY_DETAILS_CHARS = 6_000


def _truncate_advisory_text(
    text: str,
    limit: int = MAX_ADVISORY_DETAILS_CHARS,
) -> str:
    cleaned = (text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 16].rstrip() + "\n...[truncated]"


def _append_advisory_detail_block(
    detail_blocks: list[tuple[str, str]],
    seen_details: set[str],
    label: str,
    detail: str,
) -> None:
    cleaned = (detail or "").strip()
    if not cleaned or cleaned in seen_details:
        return
    seen_details.add(cleaned)
    detail_blocks.append((label, _truncate_advisory_text(cleaned)))


def _collect_advisory_detail_blocks(
    advisories: dict,
    summary: str,
) -> list[tuple[str, str]]:
    raw = advisories.get("raw") or {}
    detail_blocks: list[tuple[str, str]] = []
    seen_details: set[str] = {summary} if summary else set()

    for label, key, field in (
        ("GHSA details", "osv_ghsa", "details"),
        ("OSV details", "osv", "details"),
    ):
        source = raw.get(key) or {}
        _append_advisory_detail_block(
            detail_blocks,
            seen_details,
            label,
            source.get(field) or "",
        )

    github_items = (raw.get("github_search") or {}).get("items", []) or []
    if github_items:
        item = github_items[0]
        _append_advisory_detail_block(
            detail_blocks,
            seen_details,
            "GitHub advisory body",
            "\n\n".join(
                part
                for part in (
                    (item.get("title") or "").strip(),
                    (item.get("body") or "").strip(),
                )
                if part
            ),
        )

    return detail_blocks


def _summarize_advisory_sources(advisories: dict) -> str:
    raw = advisories.get("raw") or {}
    source_status: list[str] = []
    for source in advisories.get("sources", []) or []:
        value = raw.get(source)
        if isinstance(value, dict) and value:
            source_status.append(f"{source}:available")
        elif value not in (None, ""):
            source_status.append(f"{source}:metadata-only")
        else:
            source_status.append(f"{source}:unavailable")
    return ", ".join(source_status) if source_status else "none"


def _collect_missing_advisory_inputs(advisories: dict) -> list[str]:
    missing: list[str] = []
    if not advisories.get("affected_packages"):
        missing.append("affected package/ecosystem identification")
    if not advisories.get("affected_ranges") and not advisories.get(
        "affected_versions"
    ):
        missing.append("affected version ranges or explicit affected versions")
    if not advisories.get("fixed_versions"):
        missing.append("fixed version information")
    if not advisories.get("cvss"):
        missing.append("CVSS scoring data")
    if not advisories.get("vulnerable_symbols"):
        missing.append("vulnerable symbols or API entry points")
    if not advisories.get("summary"):
        missing.append("advisory summary")
    return missing


def build_advisory_analysis_input(
    vuln_id: str,
    advisories: dict,
    user_guidance: str = "",
) -> str:
    summary = (advisories.get("summary") or "").strip()
    missing_inputs = _collect_missing_advisory_inputs(advisories)
    data_warnings = advisories.get("data_warnings", []) or []
    source_summary = _summarize_advisory_sources(advisories)
    sections = [
        f"Vuln: {vuln_id}",
        f"Vulnerability sources used: {source_summary}",
        f"Affected packages: {advisories.get('affected_packages', [])}",
        f"CWEs: {advisories.get('cwe', [])}",
        f"Affected ranges: {advisories.get('affected_ranges', [])}",
        f"Affected versions: {advisories.get('affected_versions', [])}",
        f"Fixed versions: {advisories.get('fixed_versions', [])}",
        f"CVSS: {advisories.get('cvss', [])}",
        f"Vulnerable symbols: {advisories.get('vulnerable_symbols', [])}",
        f"Summary: {summary}",
    ]

    if data_warnings:
        sections.append("Advisory data warnings:")
        sections.extend(f"- {warning}" for warning in data_warnings)

    if missing_inputs:
        sections.append("Critical advisory gaps for analysis:")
        sections.extend(f"- Missing {item}" for item in missing_inputs)
        sections.append(
            "Additional source request: During analysis and web research, prioritize NVD, MITRE, vendor advisories, and other authoritative references to recover the missing fields above. Prefer NVD for version ranges, CPEs, CVSS, and CWE confirmation when the current advisory source lacks them."
        )

    detail_blocks = _collect_advisory_detail_blocks(advisories, summary)
    if detail_blocks:
        sections.append("Advisory details (verbatim markdown/plaintext):")
        for label, detail in detail_blocks:
            sections.append(f"[{label}]\n{detail}")

    if user_guidance:
        sections.append(f"ANALYST GUIDANCE:\n{user_guidance}")

    return "\n\n".join(sections)


def list_project_manifests(repo_path: str | None) -> list[str]:
    if not repo_path or not os.path.isdir(repo_path):
        return []
    manifests: set[str] = set()
    max_depth = 4
    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        depth = 0 if rel_root == "." else rel_root.count(os.sep) + 1
        if depth > max_depth:
            dirs[:] = []
            continue

        dirs[:] = [
            directory
            for directory in dirs
            if not directory.startswith(".")
            and directory not in {"node_modules", "dist", "build"}
        ]
        for filename in files:
            if filename in web_fetcher._ECOSYSTEM_HINTS:
                relative_path = (
                    filename
                    if rel_root == "."
                    else os.path.join(rel_root, filename)
                )
                manifests.add(relative_path)
    return sorted(manifests)


def get_scan_target(state: PipelineState) -> str:
    targets = state.get("scan_targets") or []
    return targets[0] if targets else state["component_name"]
