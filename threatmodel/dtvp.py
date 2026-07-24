#!/usr/bin/env python3
"""OWASP pytm model for DTVP, Agentyzer, and their external integrations."""

from __future__ import annotations

from collections.abc import Iterable

from pytm import (
    Action,
    Actor,
    Agent,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    DatastoreType,
    ExternalEntity,
    LLM,
    Lifetime,
    Server,
    TLSVersion,
    TM,
)


def _harden_service(service: Server) -> None:
    """Describe controls shared by the two HTTP application services."""
    service.implementsAPI = True
    service.handlesResources = True
    service.usesEnvironmentVariables = True
    service.controls.authenticatesSource = True
    service.controls.authorizesSource = True
    service.controls.checksInputBounds = True
    service.controls.definesConnectionTimeout = True
    service.controls.encodesHeaders = True
    service.controls.encodesOutput = True
    service.controls.handlesCrashes = True
    service.controls.handlesInterruptions = True
    service.controls.handlesResourceConsumption = True
    service.controls.hasAccessControl = True
    service.controls.implementsAuthenticationScheme = True
    service.controls.implementsPOLP = True
    service.controls.implementsServerSideValidation = True
    service.controls.implementsStrictHTTPValidation = True
    service.controls.isHardened = True
    service.controls.sanitizesInput = True
    service.controls.tracksExecutionFlow = True
    service.controls.usesSecureFunctions = True
    service.controls.validatesContentType = True
    service.controls.validatesHeaders = True
    service.controls.validatesInput = True


def _mark_tls_endpoint(entity: ExternalEntity | Server) -> None:
    """Mark an HTTPS endpoint whose internals are outside this model."""
    entity.port = 443
    entity.protocol = "HTTPS"
    entity.controls.isEncrypted = True
    entity.controls.authenticatesSource = True
    entity.controls.hasAccessControl = True
    entity.controls.isHardened = True


def _flow(
    source: Actor | Agent | Datastore | ExternalEntity | LLM | Server,
    sink: Actor | Agent | Datastore | ExternalEntity | LLM | Server,
    name: str,
    *,
    data: Data | Iterable[Data],
    protocol: str,
    port: int = -1,
    encrypted: bool = False,
    authenticates_destination: bool = False,
    authenticates_source: bool = False,
    authorizes_source: bool = False,
    response_to: Dataflow | None = None,
    note: str = "",
) -> Dataflow:
    """Create a bounded dataflow with explicit transport controls."""
    flow = Dataflow(
        source,
        sink,
        name,
        data=data,
        protocol=protocol,
        dstPort=port,
        tlsVersion=TLSVersion.TLSv12 if encrypted else TLSVersion.NONE,
        maxClassification=Classification.SECRET,
        responseTo=response_to,
        note=note,
    )
    flow.controls.isEncrypted = encrypted
    flow.controls.authenticatesDestination = authenticates_destination
    flow.controls.checksDestinationRevocation = authenticates_destination
    flow.controls.authenticatesSource = authenticates_source
    flow.controls.authorizesSource = authorizes_source
    flow.controls.definesConnectionTimeout = True
    flow.controls.providesConfidentiality = encrypted
    flow.controls.providesIntegrity = encrypted
    flow.controls.validatesInput = True
    return flow


def build_model() -> TM:
    """Build and return a fresh model without processing CLI arguments."""
    TM.reset()
    model = TM(
        "DTVP and Agentyzer",
        description=(
            "DTVP authenticates reviewers, exchanges vulnerability information "
            "with a selected external backend, requests threat rescoring from "
            "vscorer, and delegates source analysis to Agentyzer. Agentyzer "
            "clones approved repositories, invokes a configured LLM, and performs "
            "bounded public research. External service internals are out of scope; "
            "their interfaces and the data sent to them are in scope."
        ),
        isOrdered=True,
        mergeResponses=True,
        onDuplicates=Action.NO_ACTION,
        assumptions=[
            {
                "name": "Privileged deployment operator",
                "description": (
                    "The container host and Arcane or Compose operator can read "
                    "mounted secrets and application volumes."
                ),
            },
            {
                "name": "Approved external services",
                "description": (
                    "Operators configure trusted IdP, vulnerability-backend, "
                    "vscorer, Git, and LLM endpoints with normal TLS validation."
                ),
            },
            {
                "name": "Single writer per local volume",
                "description": (
                    "One DTVP scheduler and one Agentyzer executor operate on each "
                    "local state volume."
                ),
            },
        ],
    )

    deployment = Boundary(
        "DTVP deployment",
        description="Operator-controlled container host and network policy.",
        maxClassification=Classification.SECRET,
    )
    dtvp_boundary = Boundary(
        "DTVP service",
        description="Authenticated vulnerability-management application.",
        inBoundary=deployment,
        maxClassification=Classification.SECRET,
    )
    agentyzer_boundary = Boundary(
        "Agentyzer service",
        description="Token-authenticated source-analysis application.",
        inBoundary=deployment,
        maxClassification=Classification.SECRET,
    )
    state_boundary = Boundary(
        "Local state volumes",
        description=(
            "DTVP durable state and the separately disposable Agentyzer clone cache."
        ),
        inBoundary=deployment,
        maxClassification=Classification.SECRET,
    )
    external_boundary = Boundary(
        "External services",
        description="Independently operated identity, backend, source, and AI systems.",
        maxClassification=Classification.SECRET,
    )

    reviewer = Actor(
        "Reviewer or analyst",
        description="OIDC-authenticated human using a browser.",
        maxClassification=Classification.SECRET,
    )

    dtvp_ingress = Server(
        "DTVP ingress or reverse proxy",
        description=(
            "TLS termination and host-validated routing in front of DTVP. This "
            "may be packaged nginx or an operator-managed reverse proxy."
        ),
        inBoundary=dtvp_boundary,
        maxClassification=Classification.SECRET,
        minTLSVersion=TLSVersion.TLSv12,
        sourceFiles=[
            "../nginx.conf.template",
            "../compose.yml",
            "../deploy/arcane/compose.yml",
        ],
        usesSessionTokens=True,
    )
    _mark_tls_endpoint(dtvp_ingress)
    dtvp_ingress.controls.encodesHeaders = True
    dtvp_ingress.controls.implementsStrictHTTPValidation = True
    dtvp_ingress.controls.validatesHeaders = True
    dtvp_ingress.controls.validatesInput = True

    dtvp_api = Server(
        "DTVP API",
        description=(
            "FastAPI service enforcing OIDC sessions, roles, backend namespace "
            "isolation, bounded input, audit, and integration policy."
        ),
        inBoundary=dtvp_boundary,
        maxClassification=Classification.SECRET,
        minTLSVersion=TLSVersion.TLSv12,
        sourceFiles=[
            "../dtvp/main.py",
            "../dtvp/auth.py",
            "../dtvp/vulnerability_backend.py",
            "../dtvp/tmrescore_integration.py",
            "../dtvp/code_analysis_integration.py",
        ],
        port=8000,
        protocol="HTTP",
        OS="Alpine Linux container",
        usesSessionTokens=True,
    )
    _harden_service(dtvp_api)
    dtvp_api.controls.encryptsCookies = True
    dtvp_api.controls.encryptsSessionData = True
    dtvp_api.controls.implementsCSRFToken = True
    dtvp_api.controls.implementsNonce = True
    dtvp_api.controls.usesStrongSessionIdentifiers = True
    dtvp_api.controls.verifySessionIdentifiers = True

    agentyzer_api = Server(
        "Agentyzer API",
        description=(
            "FastAPI service enforcing independent service/admin bearer tokens, "
            "owner scope, queue admission, and filesystem constraints."
        ),
        inBoundary=agentyzer_boundary,
        maxClassification=Classification.SECRET,
        sourceFiles=[
            "../agentyzer/src/main.py",
            "../agentyzer/src/security.py",
            "../agentyzer/src/job_runtime.py",
        ],
        port=8000,
        protocol="HTTP",
        OS="Alpine Linux container",
    )
    _harden_service(agentyzer_api)

    analysis_agent = Agent(
        "Agentyzer assessment pipeline",
        description=(
            "Bounded multi-stage analysis pipeline using approved repository, "
            "research, and LLM tools; outputs require human review."
        ),
        inBoundary=agentyzer_boundary,
        maxClassification=Classification.SENSITIVE,
        sourceFiles=[
            "../agentyzer/src/pipeline/graph.py",
            "../agentyzer/src/agents",
            "../agentyzer/src/llm",
        ],
        usesExternalTools=True,
        validatesToolLaunchConfig=True,
    )
    analysis_agent.controls.hasAccessControl = True
    analysis_agent.controls.implementsPOLP = True
    analysis_agent.controls.isHardened = True
    analysis_agent.controls.sanitizesInput = True
    analysis_agent.controls.validatesInput = True

    dtvp_state = Datastore(
        "DTVP durable state",
        description=(
            "Backend-scoped caches, queues, results, audits, archives, and "
            "backup-status data."
        ),
        inBoundary=state_boundary,
        maxClassification=Classification.SECRET,
        sourceFiles=["../dtvp/configuration.py", "../dtvp/storage_health.py"],
        type=DatastoreType.FILE_SYSTEM,
        storesLogData=True,
        storesSensitiveData=True,
        hasWriteAccess=True,
        isSQL=False,
    )
    dtvp_state.controls.hasAccessControl = True
    dtvp_state.controls.implementsPOLP = True
    dtvp_state.controls.isHardened = True

    agentyzer_state = Datastore(
        "Disposable Agentyzer repository and job state",
        description=(
            "Credential-free clone objects, detached worktrees, and local job "
            "records. This volume is excluded from DTVP backups."
        ),
        inBoundary=state_boundary,
        maxClassification=Classification.SENSITIVE,
        sourceFiles=[
            "../agentyzer/src/job_store.py",
            "../agentyzer/src/agents/dependency_scanner.py",
        ],
        type=DatastoreType.FILE_SYSTEM,
        storesLogData=True,
        storesSensitiveData=True,
        hasWriteAccess=True,
        isSQL=False,
    )
    agentyzer_state.controls.hasAccessControl = True
    agentyzer_state.controls.implementsPOLP = True
    agentyzer_state.controls.isHardened = True

    identity_provider = ExternalEntity(
        "OIDC identity provider",
        description="External authorization server, discovery, JWKS, and token issuer.",
        inBoundary=external_boundary,
        inScope=False,
        maxClassification=Classification.SECRET,
        minTLSVersion=TLSVersion.TLSv12,
    )
    _mark_tls_endpoint(identity_provider)
    vulnerability_backend = ExternalEntity(
        "Vulnerability backend",
        description=(
            "Selected vendor-neutral backend instance providing findings, "
            "assessments, projects, and SBOM import."
        ),
        inBoundary=external_boundary,
        inScope=False,
        maxClassification=Classification.SECRET,
        minTLSVersion=TLSVersion.TLSv12,
    )
    _mark_tls_endpoint(vulnerability_backend)
    vscorer = ExternalEntity(
        "vscorer threat-rescoring service",
        description=(
            "External tmrescore/vscorer API accepting a threat model and SBOM, "
            "then returning an immediate result or asynchronous task reference."
        ),
        inBoundary=external_boundary,
        inScope=False,
        maxClassification=Classification.SENSITIVE,
        minTLSVersion=TLSVersion.TLSv12,
    )
    _mark_tls_endpoint(vscorer)
    git_hosts = ExternalEntity(
        "Approved Git hosts",
        description=(
            "Configured source repositories reached with child-process credentials."
        ),
        inBoundary=external_boundary,
        inScope=False,
        maxClassification=Classification.SENSITIVE,
        minTLSVersion=TLSVersion.TLSv12,
    )
    git_hosts.port = 443
    git_hosts.protocol = "Git over HTTPS or SSH"
    git_hosts.controls.isEncrypted = True
    git_hosts.controls.authenticatesSource = True
    git_hosts.controls.hasAccessControl = True
    git_hosts.controls.isHardened = True
    research_web = ExternalEntity(
        "Public research sites",
        description="Allowlisted public advisory and package metadata endpoints.",
        inBoundary=external_boundary,
        inScope=False,
        maxClassification=Classification.PUBLIC,
        minTLSVersion=TLSVersion.TLSv12,
    )
    _mark_tls_endpoint(research_web)
    llm_provider = LLM(
        "Configured LLM provider",
        description=(
            "Operator-approved Ollama or OpenWebUI-compatible model endpoint "
            "receiving source-derived prompts and returning untrusted output."
        ),
        inBoundary=external_boundary,
        maxClassification=Classification.SENSITIVE,
        minTLSVersion=TLSVersion.TLSv12,
        isThirdParty=True,
        isSelfHosted=False,
        processesPersonalData=True,
        retainsUserData=False,
        hasAgentCapabilities=False,
        hasAccessToSensitiveSystems=False,
        executesCode=False,
        hasContentFiltering=False,
        hasSystemPrompt=True,
        processesUntrustedInput=True,
        hasRAG=False,
        hasFineTuning=False,
    )
    llm_provider.protocol = "HTTP(S) OpenAI-compatible API"

    analysis_agent.protocol = "In-process"
    dtvp_state.protocol = "Local filesystem and SQLite"
    agentyzer_state.protocol = "Local filesystem and SQLite"

    browser_request = Data(
        "Authenticated browser request",
        description="Session cookie, filters, uploads, and review mutations.",
        format="HTTPS/JSON or multipart",
        classification=Classification.SECRET,
        isCredentials=True,
        credentialsLife=Lifetime.SHORT,
    )
    vulnerability_data = Data(
        "Vulnerability and assessment data",
        description="SBOMs, findings, assessments, CVSS decisions, and team mappings.",
        format="JSON and CycloneDX",
        classification=Classification.SENSITIVE,
        isStored=True,
    )
    oidc_material = Data(
        "OIDC authorization material",
        description="PKCE transaction, authorization code, ID token, and JWKS.",
        format="HTTPS parameters and JWT",
        classification=Classification.SECRET,
        isCredentials=True,
        credentialsLife=Lifetime.SHORT,
    )
    service_request = Data(
        "Code-analysis request",
        description=(
            "Repository target, vulnerability context, reviewer guidance, owner, "
            "and scoped bearer token."
        ),
        format="HTTP/JSON",
        classification=Classification.SECRET,
        isCredentials=True,
        credentialsLife=Lifetime.MANUAL,
    )
    source_code = Data(
        "Repository source",
        description="Private or public source, manifests, lockfiles, and Git metadata.",
        format="Git objects and files",
        classification=Classification.SENSITIVE,
        isStored=True,
    )
    analysis_result = Data(
        "Agentyzer analysis result",
        description=(
            "Evidence, pipeline trace, findings, verdict, and follow-up context."
        ),
        format="JSON",
        classification=Classification.SENSITIVE,
        isStored=True,
    )
    llm_prompt = Data(
        "Source-derived LLM prompt and output",
        description=(
            "System instructions, untrusted source/advisory context, model output, "
            "and optional tool calls."
        ),
        format="OpenAI-compatible chat JSON",
        classification=Classification.SENSITIVE,
    )
    research_data = Data(
        "Public research content",
        description="Untrusted advisory, package, and source metadata.",
        format="HTTPS text or JSON",
        classification=Classification.PUBLIC,
    )
    rescoring_bundle = Data(
        "vscorer rescoring bundle",
        description=(
            "Threat-model document, analysis SBOM, optional item selection, and "
            "optional vscorer configuration."
        ),
        format="HTTPS multipart",
        classification=Classification.SENSITIVE,
    )
    rescoring_result = Data(
        "vscorer task and result",
        description="Task identifier/status or completed threat-rescoring assessment.",
        format="HTTPS/JSON",
        classification=Classification.SENSITIVE,
    )

    browser_to_ingress = _flow(
        reviewer,
        dtvp_ingress,
        "Send authenticated browser request",
        data=browser_request,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        dtvp_ingress,
        reviewer,
        "Return browser response",
        data=vulnerability_data,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=browser_to_ingress,
    )
    review_request = _flow(
        dtvp_ingress,
        dtvp_api,
        "Forward authenticated review request",
        data=browser_request,
        protocol="HTTP",
        port=8000,
        authenticates_source=True,
        authorizes_source=True,
        note="Host-local or container-network hop after TLS termination.",
    )
    _flow(
        dtvp_api,
        dtvp_ingress,
        "Return portfolio and mutation result",
        data=vulnerability_data,
        protocol="HTTP",
        port=8000,
        authenticates_source=True,
        response_to=review_request,
    )

    oidc_request = _flow(
        dtvp_api,
        identity_provider,
        "Discover provider and exchange authorization code",
        data=oidc_material,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
    )
    _flow(
        identity_provider,
        dtvp_api,
        "Return discovery, JWKS, and signed tokens",
        data=oidc_material,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=oidc_request,
    )

    backend_request = _flow(
        dtvp_api,
        vulnerability_backend,
        "Read findings and write authorized assessments",
        data=vulnerability_data,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        vulnerability_backend,
        dtvp_api,
        "Return backend resources and mutation result",
        data=vulnerability_data,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=backend_request,
    )

    rescore_request = _flow(
        dtvp_api,
        vscorer,
        "Submit threat model and SBOM for rescoring",
        data=rescoring_bundle,
        protocol="HTTPS multipart",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        note="POST to the configured tmrescore/vscorer base URL.",
    )
    _flow(
        vscorer,
        dtvp_api,
        "Return immediate result or asynchronous task reference",
        data=rescoring_result,
        protocol="HTTPS/JSON",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=rescore_request,
    )
    rescore_poll = _flow(
        dtvp_api,
        vscorer,
        "Poll asynchronous vscorer task",
        data=rescoring_result,
        protocol="HTTPS/JSON",
        port=443,
        encrypted=True,
        authenticates_destination=True,
    )
    _flow(
        vscorer,
        dtvp_api,
        "Return vscorer task status or completed assessment",
        data=rescoring_result,
        protocol="HTTPS/JSON",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=rescore_poll,
    )

    analysis_request = _flow(
        dtvp_api,
        agentyzer_api,
        "Submit scoped code-analysis job",
        data=service_request,
        protocol="HTTP/JSON",
        port=8000,
        authenticates_source=True,
        authorizes_source=True,
        note=(
            "Bearer service/admin token on an internal analysis network; the "
            "packaged topology does not add transport encryption."
        ),
    )
    _flow(
        agentyzer_api,
        dtvp_api,
        "Return job status and analysis result",
        data=analysis_result,
        protocol="HTTP/JSON",
        port=8000,
        authenticates_source=True,
        response_to=analysis_request,
    )

    dispatch = _flow(
        agentyzer_api,
        analysis_agent,
        "Dispatch admitted assessment pipeline",
        data=service_request,
        protocol="In-process",
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        analysis_agent,
        agentyzer_api,
        "Return evidence and verdict",
        data=analysis_result,
        protocol="In-process",
        authenticates_source=True,
        response_to=dispatch,
    )

    clone_request = _flow(
        analysis_agent,
        git_hosts,
        "Clone or update approved repository",
        data=source_code,
        protocol="Git over HTTPS or SSH",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        git_hosts,
        analysis_agent,
        "Return repository objects",
        data=source_code,
        protocol="Git over HTTPS or SSH",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=clone_request,
    )

    research_request = _flow(
        analysis_agent,
        research_web,
        "Fetch allowlisted public research",
        data=research_data,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
    )
    _flow(
        research_web,
        analysis_agent,
        "Return untrusted research content",
        data=research_data,
        protocol="HTTPS",
        port=443,
        encrypted=True,
        authenticates_destination=True,
        response_to=research_request,
    )

    llm_request = _flow(
        analysis_agent,
        llm_provider,
        "Submit source-derived model prompt",
        data=llm_prompt,
        protocol="HTTP(S) OpenAI-compatible API",
        note=(
            "The endpoint may be a host-local Ollama service over HTTP or an "
            "operator-approved remote service over HTTPS."
        ),
    )
    _flow(
        llm_provider,
        analysis_agent,
        "Return untrusted model output and tool calls",
        data=llm_prompt,
        protocol="HTTP(S) OpenAI-compatible API",
        response_to=llm_request,
    )

    state_write = _flow(
        dtvp_api,
        dtvp_state,
        "Persist DTVP-owned state",
        data=[vulnerability_data, analysis_result, rescoring_result],
        protocol="Local filesystem and SQLite",
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        dtvp_state,
        dtvp_api,
        "Read DTVP-owned state",
        data=[vulnerability_data, analysis_result, rescoring_result],
        protocol="Local filesystem and SQLite",
        authenticates_source=True,
        response_to=state_write,
    )

    repo_write = _flow(
        analysis_agent,
        agentyzer_state,
        "Persist disposable clones, worktrees, and job records",
        data=[source_code, analysis_result],
        protocol="Local filesystem and SQLite",
        authenticates_source=True,
        authorizes_source=True,
    )
    _flow(
        agentyzer_state,
        analysis_agent,
        "Read clones and job context",
        data=[source_code, analysis_result],
        protocol="Local filesystem and SQLite",
        authenticates_source=True,
        response_to=repo_write,
    )

    return model


if __name__ == "__main__":
    build_model().process()
