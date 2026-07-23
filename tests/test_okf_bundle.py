from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-okf.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_okf", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_okf_bundle_is_valid():
    validator = _load_validator()

    assert validator.validate_bundle(ROOT / "docs", ROOT) == []


def test_validator_rejects_missing_type_and_unindexed_concepts(tmp_path: Path):
    bundle = tmp_path / "docs"
    bundle.mkdir()
    (bundle / "index.md").write_text(
        '---\nokf_version: "0.1"\n---\n\n# Test Bundle\n',
        encoding="utf-8",
    )
    (bundle / "concept.md").write_text(
        "---\ntitle: Missing type\nsource_paths: [docs]\n"
        "review_when: [Docs change]\n---\n",
        encoding="utf-8",
    )
    validator = _load_validator()

    errors = validator.validate_bundle(bundle, tmp_path)

    assert any("type must be a non-empty string" in error for error in errors)
    assert any("missing direct entry for concept.md" in error for error in errors)


def test_validator_rejects_broken_and_escaping_local_links(tmp_path: Path):
    bundle = tmp_path / "docs"
    bundle.mkdir()
    (bundle / "index.md").write_text(
        '---\nokf_version: "0.1"\n---\n\n'
        "# Test Bundle\n\n"
        "- [Concept](concept.md)\n",
        encoding="utf-8",
    )
    (bundle / "concept.md").write_text(
        "---\n"
        "type: Reference\n"
        "title: Concept\n"
        "source_paths: [docs]\n"
        "review_when: [Docs change]\n"
        "---\n\n"
        "[Missing](missing.md)\n\n"
        "[Outside](../../outside.md)\n",
        encoding="utf-8",
    )
    validator = _load_validator()

    errors = validator.validate_bundle(bundle, tmp_path)

    assert any("broken local link: missing.md" in error for error in errors)
    assert any("local link escapes repository" in error for error in errors)
