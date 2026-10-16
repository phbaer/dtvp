import re
import weakref
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from dtvp.api import legacy_router, router
from dtvp.api_advisory_jobs import router as advisory_jobs_router
from dtvp.api_agentyzer_results import router as agentyzer_results_router
from dtvp.api_analysis import legacy_router as legacy_analysis_router
from dtvp.api_analysis import router as analysis_router
from dtvp.api_analysis_jobs import router as analysis_jobs_router
from dtvp.api_assembly_editor import router as assembly_editor_router
from dtvp.api_assessment_archive import router as assessment_archive_router
from dtvp.api_bulk_reviews import router as bulk_reviews_router
from dtvp.api_component_inventory import router as component_inventory_router
from dtvp.api_coverage import router as coverage_router
from dtvp.api_cpe_editor import router as cpe_editor_router
from dtvp.api_cpe_ranking import router as cpe_ranking_router
from dtvp.api_cpe_sources import router as cpe_sources_router
from dtvp.api_documents import router as documents_router
from dtvp.api_evidence import router as evidence_router
from dtvp.api_evidence_intake import router as evidence_intake_router
from dtvp.api_history import router as history_router
from dtvp.api_identity import router as identity_router
from dtvp.api_input_quality import router as input_quality_router
from dtvp.api_intake import router as intake_router
from dtvp.api_integration_events import router as integration_events_router
from dtvp.api_intelligence_comparison import router as intelligence_comparison_router
from dtvp.api_inventory import legacy_router as legacy_inventory_router
from dtvp.api_inventory import router as inventory_router
from dtvp.api_issued_exports import router as issued_exports_router
from dtvp.api_knowledge import router as knowledge_router
from dtvp.api_legacy_archive import router as legacy_archive_router
from dtvp.api_legacy_archive_migration import router as legacy_archive_migration_router
from dtvp.api_licenses import router as licenses_router
from dtvp.api_metadata import router as metadata_router
from dtvp.api_metadata_editor import router as metadata_editor_router
from dtvp.api_migration import router as migration_router
from dtvp.api_observations import router as observations_router
from dtvp.api_osv_matching import router as osv_matching_router
from dtvp.api_ownership_editor import router as ownership_editor_router
from dtvp.api_pipeline_config import router as pipeline_config_router
from dtvp.api_pipeline_summary import router as pipeline_summary_router
from dtvp.api_portfolio import router as portfolio_router
from dtvp.api_proposals import router as proposal_router
from dtvp.api_reconciliation import router as reconciliation_router
from dtvp.api_reconciliation_catalog import router as reconciliation_catalog_router
from dtvp.api_rescoring import legacy_router as legacy_rescoring_router
from dtvp.api_rescoring import router as rescoring_router
from dtvp.api_source_jobs import router as source_jobs_router
from dtvp.api_sync_jobs import router as sync_jobs_router
from dtvp.api_synchronization import router as synchronization_router
from dtvp.api_workflow import router as workflow_router
from dtvp.auth import authenticate
from dtvp.config import Settings
from dtvp.db import engine_for, migrate, schema_ready, sessions
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.maintenance_lock import RuntimeLease
from dtvp.knowledge.projection import catch_up, is_current
from dtvp.oidc import install_oidc
from dtvp.playground import legacy_router as legacy_playground_router
from dtvp.playground import router as playground_router
from dtvp.playground import seed
from dtvp.statistics import router as statistics_router
from dtvp.storage import Artifacts


def create_app(settings=None):
    settings = settings or Settings()
    lease = RuntimeLease(settings.artifact_dir / "knowledge")
    try:
        app = _create_app(settings, lease)
    except BaseException:
        lease.close()
        raise
    weakref.finalize(app, lease.close)
    return app


def _create_app(settings, lease):
    engine = engine_for(settings.database_url)
    factory = sessions(engine)
    artifacts = Artifacts(settings.artifact_dir)
    knowledge = Journal(settings.artifact_dir / "knowledge")

    @asynccontextmanager
    async def lifespan(app):
        # Re-entry (for example repeated test-client lifespans) must reacquire
        # exclusion after the previous lifespan released the construction lease.
        lifespan_lease = RuntimeLease(settings.artifact_dir / "knowledge")
        migration_engine = None
        try:
            migration_engine = (
                engine_for(settings.migration_database_url)
                if settings.migration_database_url
                else engine
            )
            migrate(migration_engine, settings.artifact_dir.parent / "migration-backups")
            catch_up(engine, knowledge)
            if settings.playground:
                with factory.begin() as db:
                    seed(db, artifacts)
            yield
        finally:
            try:
                if migration_engine is not None and migration_engine is not engine:
                    migration_engine.dispose()
            finally:
                try:
                    engine.dispose()
                finally:
                    lease.close()
                    lifespan_lease.close()

    app = FastAPI(title="DTVP", version="2.0.0", lifespan=lifespan)
    app.state.settings, app.state.sessions, app.state.artifacts = settings, factory, artifacts
    app.state.engine = engine
    app.state.knowledge = knowledge
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        https_only=settings.public_url.startswith("https://"),
        same_site="lax",
    )
    app.include_router(migration_router)
    app.include_router(legacy_archive_migration_router)
    app.include_router(router)
    app.include_router(advisory_jobs_router)
    app.include_router(integration_events_router)
    app.include_router(inventory_router)
    app.include_router(intake_router)
    app.include_router(issued_exports_router)
    app.include_router(knowledge_router)
    app.include_router(analysis_router)
    app.include_router(analysis_jobs_router)
    app.include_router(assembly_editor_router)
    app.include_router(assessment_archive_router)
    app.include_router(bulk_reviews_router)
    app.include_router(coverage_router)
    app.include_router(cpe_editor_router)
    app.include_router(cpe_ranking_router)
    app.include_router(cpe_sources_router)
    app.include_router(documents_router)
    app.include_router(agentyzer_results_router)
    if settings.legacy_review_enabled:
        for legacy in (legacy_router, legacy_analysis_router, legacy_inventory_router, legacy_rescoring_router, statistics_router):
            app.include_router(legacy)
    app.include_router(rescoring_router)
    app.include_router(reconciliation_router)
    app.include_router(reconciliation_catalog_router)
    app.include_router(workflow_router)
    app.include_router(evidence_router)
    app.include_router(evidence_intake_router)
    app.include_router(identity_router)
    app.include_router(input_quality_router)
    app.include_router(intelligence_comparison_router)
    app.include_router(proposal_router)
    app.include_router(portfolio_router)
    app.include_router(pipeline_summary_router)
    app.include_router(pipeline_config_router)
    app.include_router(sync_jobs_router)
    app.include_router(osv_matching_router)
    app.include_router(observations_router)
    app.include_router(ownership_editor_router)
    app.include_router(history_router)
    app.include_router(metadata_router)
    app.include_router(metadata_editor_router)
    app.include_router(component_inventory_router)
    app.include_router(synchronization_router)
    app.include_router(source_jobs_router)
    app.include_router(licenses_router)
    app.include_router(legacy_archive_router)
    if settings.playground:
        from dtvp.api_playground_knowledge import router as knowledge_playground_router

        app.include_router(knowledge_playground_router)
        app.include_router(playground_router)
        if settings.legacy_review_enabled:
            app.include_router(legacy_playground_router)

    @app.middleware("http")
    async def protect(request, call_next):
        archive_stream = (
            request.method == "POST"
            and re.fullmatch(
                r"/api/v3/projects/[^/]+/(?:migration/v1-archive/preview|versions/[^/]+/migration/v1-archive/(?:preview|apply)|integration-events(?:/[a-f0-9]{64}/synchronization-preview)?)",
                request.url.path,
            )
            is not None
        )
        if request.method in {"POST", "PUT", "PATCH"} and not archive_stream:
            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    return JSONResponse({"detail": "Request exceeds upload limit"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(ValueError)
    async def invalid_input(request, error):
        return JSONResponse({"detail": str(error)[:500]}, status_code=422)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/readyz")
    def ready():
        try:
            if not schema_ready(engine):
                raise ValueError("Schema not ready")
        except Exception:
            raise HTTPException(503, "Database schema is not ready") from None
        try:
            if not is_current(engine, knowledge):
                raise ValueError("Projection is not current")
        except Exception:
            raise HTTPException(503, "Native knowledge projection is not current") from None
        return {"status": "ready"}

    @app.post("/auth/logout")
    def logout(request: Request):
        with factory.begin() as db:
            actor = authenticate(request, db)
            actor.credential.revoked = True
        response = JSONResponse({"status": "signed_out"})
        response.delete_cookie("dtvp_session")
        response.delete_cookie("dtvp_csrf")
        return response

    install_oidc(app, settings, factory)

    if settings.frontend_dir.exists():

        @app.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            root = settings.frontend_dir.resolve()
            target = (root / path).resolve()
            if not target.is_relative_to(root) or path.startswith(("api/", "auth/")):
                raise HTTPException(404)
            if target.is_file():
                return FileResponse(target)
            if path.startswith("assets/"):
                raise HTTPException(404)
            return FileResponse(root / "index.html")

    return app
