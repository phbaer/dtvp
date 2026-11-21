"""Every Dockerfile builds the frontend from frontend/ plus a few files it
copies explicitly. A frontend source that imports a file from elsewhere in
the repository breaks the image build unless every Dockerfile copies it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
IMPORT = re.compile(r"""(?:from|import)\s*\(?\s*['"]([^'"]+)['"]""")


def _outside_imports() -> set[str]:
    """Repository paths (relative to the root) that frontend sources import
    from outside frontend/."""
    found: set[str] = set()
    for path in (FRONTEND / "src").rglob("*"):
        if path.suffix not in {".ts", ".vue", ".js"} or "node_modules" in path.parts:
            continue
        for target in IMPORT.findall(path.read_text(encoding="utf-8")):
            if not target.startswith("."):
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(FRONTEND)
            except ValueError:
                found.add(resolved.relative_to(ROOT).as_posix())
    return found


def _copied(dockerfile: Path) -> list[str]:
    copied = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if parts[:1] == ["COPY"] and not any(p.startswith("--from") for p in parts):
            copied.extend(part.rstrip("/") for part in parts[1:-1])
    return copied


def test_every_dockerfile_copies_what_the_frontend_imports_from_outside():
    imports = _outside_imports()
    assert imports, "expected the frontend to import shared files"
    dockerfiles = sorted(ROOT.glob("Dockerfile*"))
    assert dockerfiles
    for dockerfile in dockerfiles:
        copied = _copied(dockerfile)
        missing = sorted(
            target for target in imports
            if not any(target == source or target.startswith(source + "/") for source in copied)
        )
        assert not missing, f"{dockerfile.name} does not copy {missing}"
