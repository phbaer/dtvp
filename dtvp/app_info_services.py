import os
import tomllib
from typing import Any, Optional

from .file_io_services import read_text


def load_pyproject_metadata(cwd: Optional[str] = None) -> dict[str, Any]:
    root_dir = cwd or os.getcwd()
    pyproject_file = os.path.join(root_dir, "pyproject.toml")
    if not os.path.exists(pyproject_file):
        return {}
    with open(pyproject_file, "rb") as file_handle:
        data = tomllib.load(file_handle)
    project = data.get("project", {})
    return {
        "name": project.get("name"),
        "version": project.get("version"),
        "authors": project.get("authors", []),
        "urls": project.get("urls", {}),
    }


def load_changelog_content(cwd: Optional[str] = None) -> str:
    root_dir = cwd or os.getcwd()
    changelog_path = os.path.join(root_dir, "CHANGELOG.md")
    if not os.path.exists(changelog_path):
        return "Changelog not available."
    return read_text(changelog_path)


def get_sbom_path(filename: str, cwd: Optional[str] = None) -> Optional[str]:
    root_dir = cwd or os.getcwd()
    sbom_path = os.path.join(root_dir, "sbom", filename)
    if not os.path.exists(sbom_path):
        return None
    return sbom_path


def build_sbom_html(content: str) -> str:
    return (
        "<html><head><title>DTVP SBOM</title></head>"
        "<body><h1>DTVP CycloneDX SBOM</h1>"
        "<p><a href='/api/sbom'>Download JSON</a></p>"
        f"<pre>{content}</pre></body></html>"
    )
