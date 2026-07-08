from src.agents import dependency_scanner


def test_find_component_keeps_sbom_attributed_presence_without_repo_match(tmp_path):
    result = dependency_scanner.find_component(
        str(tmp_path),
        "left-pad",
        sbom_attributed=True,
    )

    assert result["found"] is True
    assert result["repo_found"] is False
    assert result["sbom_attributed"] is True
    assert result["presence_basis"] == "sbom_attributed"
    assert result["direct"] is False
    assert result["transitive"] is False


def test_find_component_matches_maven_group_artifact_split(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-resolver-dns</artifactId>
      <version>4.1.134.Final</version>
    </dependency>
  </dependencies>
</project>
"""
    )

    result = dependency_scanner.find_component(
        str(tmp_path),
        "io.netty:netty-resolver-dns",
    )

    assert result["found"] is True
    assert result["repo_found"] is True
    assert result["presence_basis"] == "direct"
    assert result["declared_in"] == ["pom.xml"]


def test_find_component_extracts_gradle_lock_version_for_bare_java_name(tmp_path):
    lock_dir = tmp_path / "gradle" / "dependency-locks"
    lock_dir.mkdir(parents=True)
    lockfile = lock_dir / "runtimeClasspath.lockfile"
    lockfile.write_text(
        "io.netty:netty-resolver-dns:4.1.134.Final=runtimeClasspath\n"
    )

    result = dependency_scanner.find_component(str(tmp_path), "netty")

    assert result["found"] is True
    assert result["repo_found"] is True
    assert result["presence_basis"] == "transitive"
    assert result["locked_version"] == "4.1.134.Final"
    assert result["lock_files"] == ["gradle/dependency-locks/runtimeClasspath.lockfile"]
