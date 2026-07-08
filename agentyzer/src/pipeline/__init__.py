"""Vulnerability analysis pipeline.

Public API:
    run_pipeline(vuln_id, component_cfg, ollama=None) -> dict
"""

from src.pipeline.graph import run_pipeline

__all__ = ["run_pipeline"]
