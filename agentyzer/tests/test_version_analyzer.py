import os

from git import Repo

from src.agents import version_analyzer as va


def _init_repo_with_tags(tmpdir, file_name="pyproject.toml", comp_name="example-lib"):
    repo = Repo.init(tmpdir)
    # initial content with v1
    p = os.path.join(tmpdir, file_name)
    with open(p, "w") as f:
        f.write(f"{comp_name}==1.2.3\n")
    repo.index.add([p])
    repo.index.commit("initial commit v1")
    repo.create_tag("v1.0.0")

    # update to v2
    with open(p, "w") as f:
        f.write(f"{comp_name}==2.0.0\n")
    repo.index.add([p])
    repo.index.commit("second commit v2")
    repo.create_tag("v2.0.0")

    return repo


def test_gather_component_versions_and_inventory(tmp_path):
    tmpdir = str(tmp_path)
    repo = _init_repo_with_tags(tmpdir)

    gathered = va.gather_component_versions(tmpdir, "example-lib")
    # Expect a WORKTREE entry plus two tags
    refs = [r.get("ref") for r in gathered]
    assert "WORKTREE" in refs
    assert any(t == "v1.0.0" for t in refs)
    assert any(t == "v2.0.0" for t in refs)

    # Ensure versions discovered
    versions = [v for r in gathered for v in r.get("versions", [])]
    assert "1.2.3" in versions
    assert "2.0.0" in versions

    # Define an affected range that affects 1.2.3 but not 2.0.0
    affected_ranges = [
        {"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}
    ]
    analysis = va.inventory_versions(tmpdir, "example-lib", affected_ranges)
    table = analysis.get("version_table", [])
    comparison_inputs = analysis.get("comparison_inputs", {})
    # find row for 1.2.3 and ensure marked YES
    assert any(
        row["component_version"] == "1.2.3" and row["affected"] == "YES"
        for row in table
    )
    # 2.0.0 is outside the affected range and should now be marked not affected
    assert any(
        row["component_version"] == "2.0.0" and row["affected"] == "No" for row in table
    )
    # Rows should have ref/ref_type, not tag
    for row in table:
        assert "ref" in row
        assert "ref_type" in row
    assert comparison_inputs["component_name"] == "example-lib"
    assert comparison_inputs["affected_ranges_summary"] == [
        "SEMVER range: introduced=1.0.0 fixed=1.5.0 (source=?)"
    ]


def test_inventory_versions_keeps_explicit_inputs_and_trace(tmp_path):
    tmpdir = str(tmp_path)
    _init_repo_with_tags(tmpdir)

    affected_ranges = [
        {"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}
    ]
    affected_versions = ["1.2.3", "1.3.0"]

    analysis = va.inventory_versions(
        tmpdir,
        "example-lib",
        affected_ranges,
        locked_version="1.2.3",
        affected_versions=affected_versions,
    )

    assert analysis["comparison_inputs"]["locked_version"] == "1.2.3"
    assert analysis["comparison_inputs"]["affected_versions_count"] == 2
    assert analysis["comparison_inputs"]["affected_ranges_summary"] == [
        "SEMVER range: introduced=1.0.0 fixed=1.5.0 (source=?)",
        "Explicit affected versions: 2 listed",
    ]


def test_summarize_ranges_for_debug_uses_ranges_not_versions():
    summary = va.summarize_ranges_for_debug(
        [
            {
                "type": "SEMVER",
                "event": {"introduced": "1.0.0", "fixed": "1.5.0"},
                "source": "osv",
            }
        ],
        ["1.2.3", "1.3.0", "1.4.0"],
    )

    assert summary == [
        "SEMVER range: introduced=1.0.0 fixed=1.5.0 (source=osv)",
        "Explicit affected versions: 3 listed",
    ]


def test_select_component_constraints_does_not_mix_advisory_packages():
    ranges = [
        {
            "type": "SEMVER",
            "event": {"introduced": "1.0.0", "fixed": "2.0.0"},
            "source": "osv",
            "package": "wrong-package",
        },
        {
            "type": "SEMVER",
            "event": {"introduced": "3.0.0", "fixed": "3.5.0"},
            "source": "osv",
            "package": "target-package",
        },
    ]
    entries = [
        {"version": "1.5.0", "package": "wrong-package", "source": "osv"},
        {"version": "3.2.1", "package": "target-package", "source": "osv"},
    ]
    fixed_entries = [
        {"version": "2.0.0", "package": "wrong-package", "source": "osv"},
        {"version": "3.5.0", "package": "target-package", "source": "osv"},
    ]

    selected = va.select_component_affected_constraints(
        "target-package",
        ranges,
        ["1.5.0", "3.2.1"],
        entries,
        fixed_versions=["2.0.0", "3.5.0"],
        fixed_version_entries=fixed_entries,
    )

    assert selected["affected_ranges"] == [ranges[1]]
    assert selected["affected_versions"] == ["3.2.1"]
    assert selected["fixed_versions"] == ["3.5.0"]
    assert selected["excluded_packages"] == ["wrong-package"]
    assert selected["excluded_range_count"] == 1
    assert selected["excluded_version_count"] == 1
    assert selected["excluded_fixed_version_count"] == 1


def test_osv_last_affected_limit_and_open_ended_ranges_are_respected():
    last_affected = [
        {
            "type": "SEMVER",
            "event": {"introduced": "3.0.0", "last_affected": "3.4.7"},
        }
    ]
    limit = [
        {
            "type": "SEMVER",
            "event": {"introduced": "1.0.0", "limit": "2.0.0"},
        }
    ]
    open_ended = [
        {"type": "SEMVER", "event": {"introduced": "0"}}
    ]

    assert va.version_in_affected_ranges("3.4.7", last_affected)[0] is True
    assert va.version_in_affected_ranges("3.4.8", last_affected)[0] is False
    assert va.version_in_affected_ranges("1.9.9", limit)[0] is True
    assert va.version_in_affected_ranges("2.0.0", limit)[0] is False
    assert va.version_in_affected_ranges("999.0.0", open_ended)[0] is True


def test_npm_prerelease_ranges_use_semver_not_pep440():
    angular_ranges = [
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 21.0.0-next.0, < 21.2.15",
                "fixed": "21.2.15",
            },
            "source": "github_advisory",
            "package": "@angular/core",
            "ecosystem": "npm",
        },
        {
            "type": "ECOSYSTEM",
            "event": {"range": "<= 18.2.14"},
            "source": "github_advisory",
            "package": "@angular/core",
            "ecosystem": "npm",
        },
    ]

    affected, note, trace = va.version_in_affected_ranges(
        "21.2.14",
        angular_ranges,
    )
    assert affected is True
    assert note == (
        "version falls in affected range >= 21.0.0-next.0, < 21.2.15"
    )
    assert not any("skipped unparseable" in line for line in trace)

    assert va.version_in_affected_ranges("21.2.15", angular_ranges)[0] is False


def test_unparseable_advisory_range_is_not_treated_as_safe():
    affected, note, trace = va.version_in_affected_ranges(
        "2.0.0",
        [
            {
                "type": "ECOSYSTEM",
                "event": {"range": "not a version range"},
                "source": "github_advisory",
                "ecosystem": "npm",
            },
            {
                "type": "ECOSYSTEM",
                "event": {"range": "< 1.0.0"},
                "source": "github_advisory",
                "ecosystem": "npm",
            },
        ],
    )

    assert affected is True
    assert "one or more advisory ranges could not be evaluated" in note
    assert any("assuming affected" in line for line in trace)


def test_what_if_uses_only_fix_for_current_affected_release_line():
    ranges = [
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 22.0.0-next.0, < 22.0.0-rc.2",
                "fixed": "22.0.0-rc.2",
            },
            "ecosystem": "npm",
        },
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 21.0.0-next.0, < 21.2.15",
                "fixed": "21.2.15",
            },
            "ecosystem": "npm",
        },
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 20.0.0-next.0, < 20.3.22",
                "fixed": "20.3.22",
            },
            "ecosystem": "npm",
        },
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 19.0.0-next.0, < 19.2.22",
                "fixed": "19.2.22",
            },
            "ecosystem": "npm",
        },
    ]
    what_if = va.analyze_what_if(
        {
            "version_table": [
                {
                    "ref": "LOCKED",
                    "component_version": "21.2.14",
                    "affected": "YES",
                }
            ]
        },
        ranges,
        fixed_versions=["22.0.0-rc.2", "21.2.15", "20.3.22", "19.2.22"],
    )

    assert what_if["fixed_versions"] == ["21.2.15"]
    assert what_if["remediation"] == [
        {
            "target_version": "21.2.15",
            "from_version": "21.2.14",
            "change": "21.2.14 → 21.2.15 (patch upgrade)",
        }
    ]


def test_manifest_range_is_not_reported_as_an_installed_affected_version(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"example-lib":"^1.2.3"}}',
        encoding="utf-8",
    )

    analysis = va.inventory_versions(
        str(tmp_path),
        "example-lib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "2.0.0"}}],
    )

    worktree = next(row for row in analysis["version_table"] if row["ref"] == "WORKTREE")
    assert worktree["component_version"] == "^1.2.3"
    assert worktree["affected"] == "Unknown"
    assert worktree["source"] == "manifest-constraint"
    assert "not a resolved installed version" in worktree["notes"]
    assert analysis["worst_case"]["affected"] is True
    assert "historical_affected" not in analysis["worst_case"]

    what_if = va.analyze_what_if(analysis, [])
    assert what_if["current_version"] is None
    assert what_if["component_declared_without_resolution"] is True
    assert "no resolved current version" in what_if["summary"]


def test_git_fix_commit_is_not_recommended_as_a_package_version():
    what_if = va.analyze_what_if(
        {
            "version_table": [
                {
                    "ref": "LOCKED",
                    "component_version": "1.2.3",
                    "affected": "YES",
                }
            ]
        },
        [
            {
                "type": "GIT",
                "event": {"introduced": "0", "fixed": "abc123def456"},
                "source": "osv",
            }
        ],
    )

    assert what_if["fixed_versions"] == []
    assert what_if["remediation"] == []
    assert "no fixed version is known" in what_if["summary"]


def test_release_branches_included(tmp_path):
    """Release branches (release/<semver>) should be scanned like tags."""
    tmpdir = str(tmp_path)
    repo = _init_repo_with_tags(tmpdir, comp_name="mylib")

    # Create a release branch with a different component version
    repo.create_head("release/1.0.0")
    release_branch = repo.heads["release/1.0.0"]
    release_branch.checkout()
    p = os.path.join(tmpdir, "pyproject.toml")
    with open(p, "w") as f:
        f.write("mylib==1.5.0\n")
    repo.index.add([p])
    repo.index.commit("release 1.0.0 pins mylib 1.5.0")
    # Go back to default branch
    default_branch = (
        repo.active_branch.name
        if repo.active_branch.name != "release/1.0.0"
        else repo.heads[0].name
    )
    for h in repo.heads:
        if h.name != "release/1.0.0":
            default_branch = h.name
            break
    repo.heads[default_branch].checkout()

    gathered = va.gather_component_versions(tmpdir, "mylib")
    refs = [r.get("ref") for r in gathered]
    ref_types = {r.get("ref"): r.get("ref_type") for r in gathered}

    # Should include the release branch
    assert any("release/1.0.0" in r for r in refs), f"refs: {refs}"

    # The release branch entry should be marked as branch type
    for r in gathered:
        if "release/1.0.0" in r.get("ref", ""):
            assert r["ref_type"] == "branch"
            assert "1.5.0" in r["versions"]


def test_inventory_versions_maps_affected_product_versions_to_refs(tmp_path):
    tmpdir = str(tmp_path)
    repo = _init_repo_with_tags(tmpdir, comp_name="mylib")

    repo.create_head("release/1.1")
    release_branch = repo.heads["release/1.1"]
    release_branch.checkout()
    p = os.path.join(tmpdir, "pyproject.toml")
    with open(p, "w") as f:
        f.write("mylib==1.4.0\n")
    repo.index.add([p])
    repo.index.commit("release 1.1 pins mylib 1.4.0")
    next(h for h in repo.heads if h.name != "release/1.1").checkout()

    analysis = va.inventory_versions(
        tmpdir,
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}],
        affected_product_versions=["1.1.4", "9.9.9"],
    )

    table = analysis["version_table"]
    release_row = next(row for row in table if row["ref"] == "release/1.1")
    missing_row = next(row for row in table if row["ref"] == "9.9.9")
    scanned_refs = {row["ref"] for row in table}

    assert "v1.0.0" not in scanned_refs
    assert "v2.0.0" not in scanned_refs
    assert release_row["product_version"] == "1.1.4"
    assert release_row["component_version"] == "1.4.0"
    assert release_row["affected"] == "YES"
    assert missing_row["ref_type"] == "product-version"
    assert missing_row["product_version"] == "9.9.9"
    assert missing_row["component_version"] == "-"
    assert missing_row["affected"] == "Unknown"
    assert "no matching tag, release branch" in missing_row["notes"]
    assert analysis["comparison_inputs"]["project_versions"] == [
        "1.1.4",
        "9.9.9",
    ]
    assert analysis["comparison_inputs"]["project_version_refs"] == {
        "1.1.4": ["release/1.1"]
    }
    assert analysis["comparison_inputs"]["covered_product_versions"] == [
        "1.1.4"
    ]
    assert analysis["comparison_inputs"]["verified_affected_project_versions"] == [
        "1.1.4"
    ]
    assert analysis["comparison_inputs"]["unmatched_project_versions"] == [
        "9.9.9"
    ]


def test_inventory_versions_matches_product_versions_to_tags_with_or_without_v_prefix(
    tmp_path,
):
    tmpdir = str(tmp_path)
    repo = _init_repo_with_tags(tmpdir, comp_name="mylib")
    pyproject = os.path.join(tmpdir, "pyproject.toml")

    with open(pyproject, "w") as f:
        f.write("mylib==1.4.0\n")
    repo.index.add([pyproject])
    repo.index.commit("release 1.1.4 pins mylib 1.4.0")
    repo.create_tag("1.1.4")

    with open(pyproject, "w") as f:
        f.write("mylib==1.4.1\n")
    repo.index.add([pyproject])
    repo.index.commit("release 1.2.5 pins mylib 1.4.1")
    repo.create_tag("v1.2.5")

    analysis = va.inventory_versions(
        tmpdir,
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}],
        affected_product_versions=["v1.1.4", "1.2.5"],
    )

    table = analysis["version_table"]
    unprefixed_tag = next(row for row in table if row["ref"] == "1.1.4")
    prefixed_tag = next(row for row in table if row["ref"] == "v1.2.5")

    assert unprefixed_tag["product_version"] == "v1.1.4"
    assert unprefixed_tag["component_version"] == "1.4.0"
    assert prefixed_tag["product_version"] == "1.2.5"
    assert prefixed_tag["component_version"] == "1.4.1"
    assert analysis["comparison_inputs"]["project_version_refs"] == {
        "1.2.5": ["v1.2.5"],
        "v1.1.4": ["1.1.4"],
    }


def test_release_inventory_scans_release_branches_from_all_remotes(tmp_path):
    repo = _init_repo_with_tags(str(tmp_path), comp_name="mylib")
    repo.create_remote("origin", str(tmp_path / "origin.git"))
    repo.create_remote("secondary", str(tmp_path / "secondary.git"))
    commit = repo.head.commit.hexsha
    repo.git.update_ref("refs/remotes/origin/release/2.1", commit)
    repo.git.update_ref("refs/remotes/secondary/release/2.1", commit)
    repo.git.update_ref("refs/remotes/secondary/release/2.2", commit)

    analysis = va.inventory_versions(
        str(tmp_path),
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "2.1.0"}}],
        affected_product_versions=["2.1.4", "2.2.1"],
    )

    refs = [row["ref"] for row in analysis["version_table"]]
    assert "release/2.1" in refs
    assert "secondary/release/2.1" not in refs
    assert "secondary/release/2.2" in refs
    assert analysis["comparison_inputs"]["primary_remote"] == "origin"
    assert analysis["comparison_inputs"]["excluded_remotes"] == []
    assert analysis["comparison_inputs"]["remotes_scanned"] == [
        "origin",
        "secondary",
    ]
    assert analysis["comparison_inputs"]["project_version_refs"] == {
        "2.1.4": ["release/2.1"],
        "2.2.1": ["secondary/release/2.2"],
    }


def test_default_branch_matches_project_version_from_default_metadata_file(tmp_path):
    repo = _init_repo_with_tags(str(tmp_path), comp_name="mylib")
    project_file = tmp_path / ".project.json"
    project_file.write_text('{"name":"example","version":"3.0.0"}\n')
    repo.index.add([str(project_file)])
    repo.index.commit("set current project version")
    default_branch = repo.active_branch.name

    analysis = va.inventory_versions(
        str(tmp_path),
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "9.0.0"}}],
        affected_product_versions=["3.0.0"],
    )

    branch_row = next(
        row for row in analysis["version_table"] if row["ref"] == default_branch
    )
    assert branch_row["product_versions"] == ["3.0.0"]
    assert branch_row["project_version_sources"] == [
        {"version": "3.0.0", "path": ".project.json", "field": "version"}
    ]
    assert analysis["comparison_inputs"]["project_version_refs"] == {
        "3.0.0": [default_branch]
    }


def test_default_branch_project_version_file_and_field_are_configurable(tmp_path):
    repo = _init_repo_with_tags(str(tmp_path), comp_name="mylib")
    metadata_dir = tmp_path / "config"
    metadata_dir.mkdir()
    project_file = metadata_dir / "release.json"
    project_file.write_text('{"project":{"release":"3.1.0"}}\n')
    repo.index.add([str(project_file)])
    repo.index.commit("set nested project version")
    default_branch = repo.active_branch.name

    analysis = va.inventory_versions(
        str(tmp_path),
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "9.0.0"}}],
        affected_product_versions=["3.1.0"],
        project_version_files=[
            {"path": "config/release.json", "field": "project.release"}
        ],
    )

    branch_row = next(
        row for row in analysis["version_table"] if row["ref"] == default_branch
    )
    assert branch_row["product_versions"] == ["3.1.0"]
    assert analysis["comparison_inputs"]["project_version_files"] == [
        {"path": "config/release.json", "field": "project.release"}
    ]


def test_default_branch_without_matching_metadata_is_outside_intersection(tmp_path):
    repo = _init_repo_with_tags(str(tmp_path), comp_name="mylib")
    default_branch = repo.active_branch.name

    analysis = va.inventory_versions(
        str(tmp_path),
        "mylib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "9.0.0"}}],
        affected_product_versions=["3.2.0"],
    )

    refs = {row["ref"] for row in analysis["version_table"]}
    assert default_branch not in refs
    assert analysis["comparison_inputs"]["unmatched_project_versions"] == [
        "3.2.0"
    ]


def test_historical_affected_in_worst_case(tmp_path):
    """Past releases that were affected should appear in historical_affected."""
    tmpdir = str(tmp_path)
    _init_repo_with_tags(tmpdir, comp_name="mylib")

    # v1.0.0 has mylib==1.2.3, v2.0.0 has mylib==2.0.0
    affected_ranges = [
        {"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}
    ]
    analysis = va.inventory_versions(tmpdir, "mylib", affected_ranges)
    worst = analysis["worst_case"]
    assert worst["affected"] is True
    assert "No lock files found" in worst["note"]
    historical = worst.get("historical_affected", [])
    assert len(historical) >= 1
    assert any(h["ref"] == "v1.0.0" for h in historical)


def test_gather_component_versions_uses_nested_lockfiles_in_tags(tmp_path):
    tmpdir = str(tmp_path)
    repo = Repo.init(tmpdir)
    os.makedirs(os.path.join(tmpdir, "frontend"), exist_ok=True)
    lock_path = os.path.join(tmpdir, "frontend", "npm-shrinkwrap.json")

    with open(lock_path, "w") as f:
        f.write(
            '{"packages":{"node_modules/example-lib":{"version":"1.2.3"}},"dependencies":{"example-lib":{"version":"1.2.3"}}}'
        )
    repo.index.add([lock_path])
    repo.index.commit("lock v1")
    repo.create_tag("v1.0.0")

    with open(lock_path, "w") as f:
        f.write(
            '{"packages":{"node_modules/example-lib":{"version":"2.0.0"}},"dependencies":{"example-lib":{"version":"2.0.0"}}}'
        )
    repo.index.add([lock_path])
    repo.index.commit("lock v2")
    repo.create_tag("v2.0.0")

    gathered = va.gather_component_versions(tmpdir, "example-lib")
    worktree = next(row for row in gathered if row["ref"] == "WORKTREE")
    tag_versions = {
        row["ref"]: row["versions"] for row in gathered if row["ref"] != "WORKTREE"
    }

    assert worktree["source"] == "lock"
    assert "2.0.0" in worktree["versions"]
    assert "1.2.3" in tag_versions["v1.0.0"]
    assert "2.0.0" in tag_versions["v2.0.0"]

    analysis = va.inventory_versions(
        tmpdir,
        "example-lib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "9.9.9"}}],
    )
    inputs = analysis["comparison_inputs"]
    assert inputs["lock_files_found_by_ref"]["WORKTREE"] == [
        "frontend/npm-shrinkwrap.json"
    ]
    assert inputs["lock_files_found_by_ref"]["v1.0.0"] == [
        "frontend/npm-shrinkwrap.json"
    ]
    assert inputs["lock_files_processed_by_ref"]["WORKTREE"] == [
        "frontend/npm-shrinkwrap.json"
    ]
    assert inputs["lock_files_processed_by_ref"]["v2.0.0"] == [
        "frontend/npm-shrinkwrap.json"
    ]


def test_inventory_versions_warns_and_assumes_worst_case_without_any_lockfiles(
    tmp_path,
):
    tmpdir = str(tmp_path)
    repo = Repo.init(tmpdir)
    pyproject = os.path.join(tmpdir, "pyproject.toml")
    with open(pyproject, "w") as f:
        f.write('[project]\ndependencies = ["example-lib==2.0.0"]\n')
    repo.index.add([pyproject])
    repo.index.commit("manifest only")
    repo.create_tag("v1.0.0")
    default_branch = repo.active_branch.name

    analysis = va.inventory_versions(
        tmpdir,
        "example-lib",
        [{"type": "SEMVER", "event": {"introduced": "1.0.0", "fixed": "1.5.0"}}],
    )

    worst = analysis["worst_case"]
    assert worst["affected"] is True
    assert "No lock files found" in worst["note"]
    assert worst["warnings"]
    assert analysis["comparison_inputs"]["lock_files_found"] == []
    assert analysis["comparison_inputs"]["lock_files_found_by_ref"] == {"WORKTREE": []}
    assert analysis["comparison_inputs"]["lock_files_processed_by_ref"] == {
        "WORKTREE": [],
        default_branch: [],
        "v1.0.0": [],
    }


def test_inventory_versions_trace_uses_prebuilt_github_range_strings(tmp_path):
    tmpdir = str(tmp_path)
    _init_repo_with_tags(tmpdir, comp_name="mylib")

    analysis = va.inventory_versions(
        tmpdir,
        "mylib",
        [
            {
                "type": "ECOSYSTEM",
                "event": {"range": ">= 1.0.0, <= 1.5.0"},
                "source": "github_advisory",
            }
        ],
    )

    assert any(
        line.strip()
        == "ECOSYSTEM range: >= 1.0.0, <= 1.5.0 (source=github_advisory)"
        for line in analysis["trace"]
    )


class TestAdditionalLockExtraction:
    def test_conan_lock_v1_or_v2_format(self):
        from src.agents.dependency_scanner import _extract_locked_version

        text = '{"requires":[{"ref":"zlib/1.2.13#abc","package_id":"123"}]}'
        ver = _extract_locked_version(text, "zlib", "conan.lock")
        assert ver == "1.2.13"

    def test_npm_shrinkwrap_uses_package_lock_extractor(self):
        from src.agents.dependency_scanner import _extract_locked_version

        text = '{"dependencies":{"example-lib":{"version":"2.4.1"}}}'
        ver = _extract_locked_version(text, "example-lib", "npm-shrinkwrap.json")
        assert ver == "2.4.1"


class TestJavaProjectFileParsing:
    def test_maven_pom_namespace_and_property_version(self):
        texts = {
            "pom.xml": """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <netty.version>4.1.134.Final</netty.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-resolver-dns</artifactId>
      <version>${netty.version}</version>
    </dependency>
  </dependencies>
</project>
"""
        }

        versions = va._scan_manifests_in_texts(texts, "io.netty:netty-resolver-dns")

        assert versions == ["4.1.134.Final"]

    def test_gradle_groovy_and_kotlin_dependency_notations(self):
        texts = {
            "build.gradle": """
ext.nettyVersion = "4.1.134.Final"
dependencies {
    implementation "io.netty:netty-resolver-dns:${nettyVersion}"
    runtimeOnly group: "io.netty", name: "netty-codec-http", version: "4.1.135.Final"
}
""",
            "build.gradle.kts": """
dependencies {
    implementation("io.netty:netty-all:4.1.136.Final")
    api(group = "org.keycloak", name = "keycloak-core", version = "26.0.7")
}
""",
        }

        assert va._scan_manifests_in_texts(texts, "netty-resolver-dns") == [
            "4.1.134.Final"
        ]
        assert va._scan_manifests_in_texts(texts, "io.netty:netty-codec-http") == [
            "4.1.135.Final"
        ]
        assert va._scan_manifests_in_texts(texts, "netty-all") == ["4.1.136.Final"]
        assert va._scan_manifests_in_texts(texts, "org.keycloak:keycloak-core") == [
            "26.0.7"
        ]

    def test_gradle_lockfile_extracts_group_artifact_and_bare_name(self):
        from src.agents.dependency_scanner import _extract_locked_version

        text = """
# This is a Gradle dependency lock file.
io.netty:netty-resolver-dns:4.1.134.Final=runtimeClasspath
org.keycloak:keycloak-core:26.0.7=runtimeClasspath
empty=annotationProcessor
"""

        assert (
            _extract_locked_version(
                text,
                "io.netty:netty-resolver-dns",
                "runtimeClasspath.lockfile",
            )
            == "4.1.134.Final"
        )
        assert _extract_locked_version(text, "netty", "gradle.lockfile") == (
            "4.1.134.Final"
        )

    def test_gradle_version_catalog_extracts_library_version_ref(self):
        texts = {
            "gradle/libs.versions.toml": """
[versions]
netty = "4.1.134.Final"
keycloak = "26.0.7"

[libraries]
netty-resolver-dns = { module = "io.netty:netty-resolver-dns", version.ref = "netty" }
keycloak-core = { module = "org.keycloak:keycloak-core", version.ref = "keycloak" }
"""
        }

        assert va._scan_manifests_in_texts(texts, "netty-resolver-dns") == [
            "4.1.134.Final"
        ]
        assert va._scan_manifests_in_texts(texts, "org.keycloak:keycloak-core") == [
            "26.0.7"
        ]

    def test_gather_component_versions_uses_nested_gradle_lockfiles(self, tmp_path):
        repo = Repo.init(tmp_path)
        lock_dir = tmp_path / "gradle" / "dependency-locks"
        lock_dir.mkdir(parents=True)
        lock_path = lock_dir / "runtimeClasspath.lockfile"

        lock_path.write_text(
            "io.netty:netty-resolver-dns:4.1.134.Final=runtimeClasspath\n"
        )
        repo.index.add([str(lock_path.relative_to(tmp_path))])
        repo.index.commit("lock v1")
        repo.create_tag("v1.0.0")

        lock_path.write_text(
            "io.netty:netty-resolver-dns:4.1.135.Final=runtimeClasspath\n"
        )
        repo.index.add([str(lock_path.relative_to(tmp_path))])
        repo.index.commit("lock v2")

        gathered = va.gather_component_versions(
            str(tmp_path),
            "io.netty:netty-resolver-dns",
        )
        worktree = next(row for row in gathered if row["ref"] == "WORKTREE")
        tag = next(row for row in gathered if row["ref"] == "v1.0.0")

        assert worktree["source"] == "lock"
        assert worktree["versions"] == ["4.1.135.Final"]
        assert tag["versions"] == ["4.1.134.Final"]


# ======================================================================= #
# version_in_affected_ranges — GIT-only ranges                            #
# ======================================================================= #


class TestGitOnlyRanges:
    """When advisory has only GIT ranges (commit hashes), we cannot do a
    semver comparison.  The system should assume the version IS affected
    rather than silently reporting 'not affected'."""

    GIT_RANGE = {
        "type": "GIT",
        "event": {"introduced": "0", "fixed": "abc123"},
        "source": "osv",
    }
    ECO_RANGE = {
        "type": "ECOSYSTEM",
        "event": {"introduced": "0", "fixed": "3.0.6"},
        "source": "osv_ghsa",
    }

    def test_git_only_no_versions_assumes_affected(self):
        """GIT-only ranges + no explicit versions → assumed affected."""
        is_aff, note, trace = va.version_in_affected_ranges(
            "2.0.0", [self.GIT_RANGE], None
        )
        assert is_aff is True
        assert "assumed affected" in note

    def test_git_only_with_matching_version(self):
        """GIT range + explicit versions list that includes the version → affected."""
        is_aff, note, _ = va.version_in_affected_ranges(
            "2.0.0", [self.GIT_RANGE], ["2.0.0", "2.1.0"]
        )
        assert is_aff is True
        assert "explicit affected versions list" in note

    def test_git_only_with_non_matching_version(self):
        """GIT range + explicit versions list that does NOT include version.

        The list may be incomplete, so we still assume affected.
        """
        is_aff, note, _ = va.version_in_affected_ranges(
            "2.0.0", [self.GIT_RANGE], ["1.0.0", "1.5.0"]
        )
        assert is_aff is True
        assert "assumed affected" in note

    def test_ecosystem_range_gives_definitive_answer(self):
        """ECOSYSTEM ranges should produce a definitive semver answer."""
        # In range → affected
        is_aff, note, _ = va.version_in_affected_ranges(
            "2.0.0", [self.GIT_RANGE, self.ECO_RANGE], None
        )
        assert is_aff is True
        assert "falls in affected range" in note

        # After fix → not affected
        is_aff, note, _ = va.version_in_affected_ranges(
            "3.1.0", [self.GIT_RANGE, self.ECO_RANGE], None
        )
        assert is_aff is False
        assert "outside the affected ranges" in note

    def test_cve_2024_49766_werkzeug(self):
        """Regression: werkzeug 2.0.0 must be affected by CVE-2024-49766."""
        git_range = {
            "type": "GIT",
            "event": {
                "introduced": "0",
                "fixed": "5eaefc3996aa5cc8c5237d8b82f1b89eed6ea624",
            },
            "source": "osv",
        }
        # Scenario A: GHSA fetch succeeded → ECOSYSTEM range available
        eco_range = {
            "type": "ECOSYSTEM",
            "event": {"introduced": "0", "fixed": "3.0.6"},
            "source": "osv_ghsa",
        }
        is_aff, note, _ = va.version_in_affected_ranges(
            "2.0.0", [git_range, eco_range], None
        )
        assert is_aff is True
        assert "falls in affected range" in note

        # Scenario B: GHSA fetch failed → GIT-only, no versions
        is_aff, note, _ = va.version_in_affected_ranges("2.0.0", [git_range], None)
        assert is_aff is True
        assert "assumed affected" in note

        # Scenario C: GHSA fetch failed, but CVE versions list available
        versions = ["0.1", "2.0.0", "3.0.2"]
        is_aff, note, _ = va.version_in_affected_ranges("2.0.0", [git_range], versions)
        assert is_aff is True
        assert "explicit affected versions list" in note


# ======================================================================= #
# uv.lock version extraction                                              #
# ======================================================================= #


class TestUvLockExtraction:
    def test_uv_lock_toml_format(self):
        from src.agents.dependency_scanner import _extract_locked_version

        text = """
[[package]]
name = "flask"
version = "2.3.3"

[[package]]
name = "werkzeug"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""
        ver = _extract_locked_version(text, "werkzeug", "uv.lock")
        assert ver == "2.0.0"

    def test_uv_lock_does_not_cross_packages(self):
        from src.agents.dependency_scanner import _extract_locked_version

        text = """
[[package]]
name = "flask"
version = "2.3.3"

[[package]]
name = "werkzeug"
version = "3.0.6"
"""
        # Should find werkzeug's version, not flask's
        ver = _extract_locked_version(text, "werkzeug", "uv.lock")
        assert ver == "3.0.6"


# ======================================================================= #
# PEP 508 specifier parsing in pyproject.toml                             #
# ======================================================================= #


class TestPep508Parsing:
    def test_pep508_gte_specifier(self):
        texts = {
            "pyproject.toml": (
                '[project]\ndependencies = [\n    "werkzeug>=2.0.0",\n]\n'
            )
        }
        versions = va._scan_manifests_in_texts(texts, "werkzeug")
        assert ">=2.0.0" in versions

    def test_pep508_exact_specifier(self):
        texts = {
            "pyproject.toml": (
                '[project]\ndependencies = [\n    "werkzeug==2.0.0",\n]\n'
            )
        }
        versions = va._scan_manifests_in_texts(texts, "werkzeug")
        assert "2.0.0" in versions

    def test_pep508_compatible_release(self):
        texts = {
            "pyproject.toml": ('[project]\ndependencies = [\n    "werkzeug~=2.0",\n]\n')
        }
        versions = va._scan_manifests_in_texts(texts, "werkzeug")
        assert "~=2.0" in versions

    def test_pep508_with_extras(self):
        texts = {
            "pyproject.toml": (
                '[project]\ndependencies = [\n    "werkzeug[watchdog]>=2.1.0",\n]\n'
            )
        }
        versions = va._scan_manifests_in_texts(texts, "werkzeug")
        assert ">=2.1.0" in versions
