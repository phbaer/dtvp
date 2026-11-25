"""The registry of everything River persists."""

import os
import subprocess
import sys

import pytest

from dtvp.instance_stores import resolve_instance_stores

PATH_VARIABLES = (
    "DTVP_DT_CACHE_PATH",
    "DTVP_DATABASE_PATH",
    "DTVP_ASSESSMENT_OUTBOX_PATH",
    "DTVP_ACCESS_TOKENS_PATH",
    "DTVP_CODE_ANALYSIS_RESULTS_PATH",
    "DTVP_TMRESCORE_CACHE_PATH",
    "DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH",
    "DTVP_SSVC_CACHE_PATH",
    "TEAM_MAPPING_PATH",
    "TEAM_GROUPS_PATH",
    "USER_ROLES_PATH",
    "RESCORE_RULES_PATH",
    "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH",
)


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    for variable in PATH_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return os.path.realpath(workdir)


def test_defaults_resolve_against_the_working_directory(clean_env):
    work = clean_env
    stores = resolve_instance_stores()
    dt_cache = os.path.join(work, "data", "dt_cache")
    assert stores.dt_cache_dir == dt_cache
    # The database, the outbox and the tokens share one file by default.
    assert [(s.name, s.path, s.namespaces) for s in stores.sqlite_records] == [
        (
            "main",
            os.path.join(dt_cache, "dtvp.sqlite3"),
            ("local_store", "assessment_outbox", "finding_lifecycle", "access_tokens", "saved_views"),
        ),
        (
            "code_analysis_results",
            os.path.join(work, "data", "code_analysis_results.sqlite"),
            ("code_analysis_results",),
        ),
    ]
    assert stores.json_record_path("tmrescore_proposals") == os.path.join(
        work, "data", "tmrescore_proposals.json"
    )
    assert [(item.name, item.path) for item in stores.config] == [
        ("team_mapping", os.path.join(work, "data", "team_mapping.json")),
        ("team_groups", os.path.join(work, "data", "team_groups.json")),
        ("user_roles", os.path.join(work, "data", "user_roles.json")),
        ("rescore_rules", os.path.join(work, "data", "rescore_rules.json")),
        (
            "auto_analysis_guidance",
            os.path.join(work, "data", "auto_analysis_guidance.json"),
        ),
    ]
    assert {item.name: item.path for item in stores.caches} == {
        "grouped_vuln_summary_index": os.path.join(
            work, "data", "grouped_vuln_summary_index.sqlite"
        ),
        "ssvc_enrichment": os.path.join(dt_cache, "ssvc_enrichment.sqlite3"),
        "code_analysis_diagnostics": os.path.join(
            work, "data", "code_analysis_results.sqlite.diagnostics.sqlite"
        ),
    }
    assert {item.name: item.path for item in stores.legacy_inputs} == {
        "dt_cache_json": dt_cache,
        "assessment_outbox_file": os.path.join(dt_cache, "assessment_outbox.sqlite"),
        "pending_updates": os.path.join(dt_cache, "pending_updates.json"),
        "code_analysis_results_json": os.path.join(
            work, "data", "code_analysis_results.json"
        ),
    }
    assert stores.lock_path == os.path.join(dt_cache, ".dtvp-instance.lock")
    assert stores.export_lock_path == os.path.join(dt_cache, ".dtvp-export.lock")
    assert stores.registry_path == os.path.join(dt_cache, ".dtvp-instance.json")
    assert stores.journal_glob == os.path.join(dt_cache, ".dtvp-restore-*.json")


def test_every_override_is_resolved(clean_env, monkeypatch, tmp_path):
    base = os.path.realpath(tmp_path)
    overrides = {
        "DTVP_DT_CACHE_PATH": "cache",
        "DTVP_DATABASE_PATH": f"{base}/db/main.sqlite3",
        "DTVP_ASSESSMENT_OUTBOX_PATH": f"{base}/db/outbox.sqlite3",
        "DTVP_ACCESS_TOKENS_PATH": f"{base}/db/tokens.sqlite3",
        # A configured .json path names the former JSON file.
        "DTVP_CODE_ANALYSIS_RESULTS_PATH": f"{base}/ca/results.json",
        "DTVP_TMRESCORE_CACHE_PATH": f"{base}/tm.json",
        "DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH": f"{base}/idx.sqlite",
        "DTVP_SSVC_CACHE_PATH": f"{base}/ssvc.sqlite3",
        "TEAM_MAPPING_PATH": f"{base}/cfg/tm.json",
        "TEAM_GROUPS_PATH": f"{base}/cfg/tg.json",
        "USER_ROLES_PATH": f"{base}/cfg/ur.json",
        "RESCORE_RULES_PATH": f"{base}/cfg/rr.json",
        "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH": f"{base}/cfg/ag.json",
    }
    for variable, value in overrides.items():
        monkeypatch.setenv(variable, value)
    stores = resolve_instance_stores()
    assert stores.dt_cache_dir == os.path.join(clean_env, "cache")
    assert [(s.name, s.path, s.namespaces) for s in stores.sqlite_records] == [
        ("main", f"{base}/db/main.sqlite3", ("local_store", "saved_views")),
        ("assessment_outbox", f"{base}/db/outbox.sqlite3", ("assessment_outbox", "finding_lifecycle")),
        ("access_tokens", f"{base}/db/tokens.sqlite3", ("access_tokens",)),
        ("code_analysis_results", f"{base}/ca/results.sqlite", ("code_analysis_results",)),
    ]
    caches = {item.name: item.path for item in stores.caches}
    # The diagnostics file sits beside the configured path, not the database.
    assert caches["code_analysis_diagnostics"] == f"{base}/ca/results.json.diagnostics.sqlite"
    assert caches["ssvc_enrichment"] == f"{base}/ssvc.sqlite3"
    assert caches["grouped_vuln_summary_index"] == f"{base}/idx.sqlite"
    assert stores.json_record_path("tmrescore_proposals") == f"{base}/tm.json"
    assert stores.config_path("user_roles") == f"{base}/cfg/ur.json"
    legacy = {item.name: item.path for item in stores.legacy_inputs}
    assert legacy["code_analysis_results_json"] == f"{base}/ca/results.json"
    comparable = stores.as_comparable()
    assert comparable["sqlite:assessment_outbox"] == f"{base}/db/outbox.sqlite3"
    assert comparable["config:auto_analysis_guidance"] == f"{base}/cfg/ag.json"
    assert comparable["cache:ssvc_enrichment"] == f"{base}/ssvc.sqlite3"
    assert comparable["json:tmrescore_proposals"] == f"{base}/tm.json"


def test_only_the_outbox_split_keeps_tokens_in_the_main_file(clean_env, monkeypatch, tmp_path):
    monkeypatch.setenv("DTVP_ASSESSMENT_OUTBOX_PATH", str(tmp_path / "outbox.sqlite"))
    stores = resolve_instance_stores()
    assert [(s.name, s.namespaces) for s in stores.sqlite_records] == [
        ("main", ("local_store", "access_tokens", "saved_views")),
        ("assessment_outbox", ("assessment_outbox", "finding_lifecycle")),
        ("code_analysis_results", ("code_analysis_results",)),
    ]


def test_symlinked_paths_are_merged(clean_env, monkeypatch, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(real))
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_PATH", str(tmp_path / "link" / "dtvp.sqlite3"))
    stores = resolve_instance_stores()
    assert stores.sqlite_records[0].namespaces == (
        "local_store",
        "assessment_outbox",
        "finding_lifecycle",
        "access_tokens",
        "saved_views",
    )


def test_registry_module_does_not_open_the_databases():
    code = (
        "import sys, dtvp.instance_stores; "
        "assert not {'dtvp.main', 'dtvp.dt_cache'} & set(sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=os.getcwd())
