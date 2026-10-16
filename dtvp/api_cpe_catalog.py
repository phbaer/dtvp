"""Project-authorized read-only search of the optional instance CPE catalog."""

from fastapi import APIRouter, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.cpe_catalog import LIMITATIONS, Catalog

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/cpe/catalog")
def catalog_status(project_id: str, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    catalog = Catalog(request.app.state.settings.artifact_dir / "cpe-catalog")
    generation = catalog.current()
    if generation is None:
        return {"available": False, "generation": None, "limitations": LIMITATIONS}
    _, manifest = catalog.manifest(generation)
    return {
        "available": True,
        "generation": generation,
        "records": manifest["records"],
        "source": manifest["source"],
        "synthetic": manifest.get("synthetic", False),
        "assurance": manifest["assurance"],
        "limitations": LIMITATIONS,
    }


@router.get("/projects/{project_id}/cpe/catalog/search")
def catalog_search(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query(min_length=2, max_length=200),
    generation: str | None = Query(None, pattern=r"^[a-f0-9]{64}$"),
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(50, ge=1, le=200),
    include_deprecated: bool = False,
):
    project_for(db, actor, project_id)
    return Catalog(request.app.state.settings.artifact_dir / "cpe-catalog").search(
        q,
        generation=generation,
        offset=offset,
        limit=limit,
        include_deprecated=include_deprecated,
    )


@router.get("/projects/{project_id}/cpe/catalog/export")
def catalog_export(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query(min_length=2, max_length=200),
    generation: str | None = Query(None, pattern=r"^[a-f0-9]{64}$"),
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(50, ge=1, le=200),
    include_deprecated: bool = False,
):
    project_for(db, actor, project_id)
    return Catalog(request.app.state.settings.artifact_dir / "cpe-catalog").export(
        q,
        generation=generation,
        offset=offset,
        limit=limit,
        include_deprecated=include_deprecated,
    )
