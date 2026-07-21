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

    assert release_row["product_version"] == "1.1.4"
    assert release_row["component_version"] == "1.4.0"
    assert release_row["affected"] == "YES"
    assert missing_row["ref_type"] == "product-version"
    assert missing_row["product_version"] == "9.9.9"
    assert missing_row["component_version"] == "-"
    assert "no matching tag or branch" in missing_row["notes"]
    assert analysis["comparison_inputs"]["affected_product_versions"] == [
        "1.1.4",
        "9.9.9",
    ]
    assert analysis["comparison_inputs"]["affected_product_version_refs"] == {
        "1.1.4": ["release/1.1"]
    }


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
    assert analysis["comparison_inputs"]["affected_product_version_refs"] == {
        "1.2.5": ["v1.2.5"],
        "v1.1.4": ["1.1.4"],
    }


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
        == "SEMVER range: >= 1.0.0, <= 1.5.0 (source=github_advisory)"
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
    def test_maven_parsers_reject_xml_entities(self):
        from src.languages.java import _pom_dependencies

        malicious_pom = """<!DOCTYPE project [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<project><dependencies><dependency>
  <groupId>&xxe;</groupId><artifactId>example</artifactId><version>1.0</version>
</dependency></dependencies></project>
"""

        assert _pom_dependencies(malicious_pom) == []
        assert va._scan_manifests_in_texts(
            {"pom.xml": malicious_pom}, "example"
        ) == []

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
        assert "2.0.0" in versions

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
        assert "2.0" in versions

    def test_pep508_with_extras(self):
        texts = {
            "pyproject.toml": (
                '[project]\ndependencies = [\n    "werkzeug[watchdog]>=2.1.0",\n]\n'
            )
        }
        versions = va._scan_manifests_in_texts(texts, "werkzeug")
        assert "2.1.0" in versions
