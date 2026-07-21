export interface Project {
    uuid: string;
    name: string;
    version: string;
    classifier: string;
    active: boolean;
}

export type BackendCapability =
    | 'project_search'
    | 'finding_read'
    | 'sbom_read'
    | 'assessment_read'
    | 'assessment_write'
    | 'sbom_upload'
    | 'project_create'
    | 'dependency_graph'
    | 'audit_history'
    | 'vex_exchange';

export interface VulnerabilityBackendDescriptor {
    id: string;
    type: string;
    label: string;
    capabilities: BackendCapability[];
}

export interface VersionInfo {
    version: string;
    build: string;
    vulnerability_backend?: VulnerabilityBackendDescriptor;
}

export type TagValue = string | { name?: string; tag?: string } | null;
export type Tags = Array<string | TagValue>;

export interface Instance {
    project_name: string;
    project_version: string;
    project_uuid: string;
    component_name: string;
    component_group?: string | null;
    component_purl?: string | null;
    component_version: string;
    component_uuid: string;
    vulnerability_uuid: string;
    finding_uuid: string;
    attributed_on?: string | number | null;
    analysis_state: string;
    analysisState?: string;
    analysis_details?: string;
    analysisDetails?: string;
    analysis_comments?: Array<{
        comment: string;
        timestamp: number;
        user?: string;
    }>;
    is_suppressed: boolean;
    is_direct_dependency?: boolean | null;
    dependency_chains?: string[];
    justification?: string;
    tags?: string[];
    assessment_restore?: AssessmentRestoreCandidate;
}


export interface AffectedVersion {
    project_name: string;
    project_version: string;
    project_uuid: string;
    components: Instance[];
}

export type GroupedVulnDependencyRelationship = 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN';
export type InconsistencyReason =
    | 'MISSING_RESCORING_VECTOR'
    | 'ANALYSIS_STATE_MISMATCH'
    | 'TEAM_ASSESSMENT_MISMATCH'
    | 'ASSESSMENT_DETAILS_MISMATCH';

export interface GroupedVulnListMetadata {
    lifecycle?: string;
    inconsistency_reasons?: InconsistencyReason[];
    is_pending?: boolean;
    is_open?: boolean;
    is_assessed?: boolean;
    technical_state?: string;
    assessed_teams?: string[];
    component_names?: string[];
    versions?: string[];
    attributed_on_ms_values?: number[];
    oldest_attributed_on_ms?: number | null;
    instance_count?: number;
    dependency_relationship?: GroupedVulnDependencyRelationship;
    cvss_version_mismatch?: boolean;
    assessment_restore_count?: number;
    assessment_restore_recoverable_count?: number;
    assessment_restore_reasons?: string[];
    assessment_restore_status?: string | null;
}

export interface AssessmentRestoreCandidate {
    reason: string;
    status: 'recoverable' | 'ambiguous' | 'no_history' | string;
    current_score?: number | null;
    restored_score?: number | null;
    restored_vector?: string | null;
    candidate_vectors?: string[];
    source?: {
        timestamp?: string | number | null;
        commenter?: string | null;
        comment_index?: number | null;
    } | null;
}

export interface GroupedVuln {
    id: string; // CVE/VulnID
    code_assessment_status?: 'auto' | 'manual' | 'mixed' | 'partial' | null;
    title?: string;
    description?: string;
    severity?: string;
    cvss?: number;
    cvss_score?: number;
    cvss_vector?: string;
    rescored_cvss?: number | null;
    rescored_vector?: string | null;
    rescored_vector_adjusted?: boolean;
    tags?: string[];
    assignees?: string[];
    aliases?: string[];
    assessment_restore_count?: number;
    assessment_restore_recoverable_count?: number;
    assessment_restore_reasons?: string[];
    assessment_restore_status?: string | null;
    list_metadata?: GroupedVulnListMetadata;
    affected_versions: AffectedVersion[];
}

export interface AssessmentPayload {
    instances: Instance[];
    state: string;
    details: string;
    justification?: string;
    suppressed: boolean;
    team?: string;
    assigned?: string[];
    original_analysis?: Record<string, any>;
    force?: boolean;
    comparison_mode?: 'MERGE' | 'REPLACE';
    analysis_run_ids?: string[];
}

export interface Statistics {
    severity_counts: Record<string, number>;
    state_counts: Record<string, number>;
    total_unique: number;
    total_findings: number;
    affected_projects_count: number;
    version_counts: Record<string, number>;
    major_version_counts?: Record<string, number>;
    major_version_details?: Record<string, Record<string, number>>;
    major_version_severity_counts?: Record<string, Record<string, number>>;
    version_severity_counts?: Record<string, Record<string, number>>;
}

export interface CacheStatus {
    backend_id?: string;
    fully_cached: boolean;
    last_refreshed_at: string | null;
    projects: number;
    active_projects: number;
    cached_findings: number;
    cached_boms: number;
    cached_analyses: number;
    pending_updates: number;
}

export interface ProjectArchiveVersionPreview {
    project_name: string;
    version: string;
    source_uuid: string;
    target_uuid?: string | null;
    target_exists: boolean;
    finding_count: number;
    vulnerability_count: number;
    assessment_count: number;
    restorable_assessment_count: number;
    bom_component_count: number;
}

export interface ProjectArchivePreview {
    schema_version: string;
    created_at?: string | null;
    project_name: string;
    versions: ProjectArchiveVersionPreview[];
    total_versions: number;
    total_assessments: number;
    total_restorable_assessments: number;
    warnings: string[];
}

export interface ProjectArchiveApplyResult {
    project_name: string;
    mode: 'create_missing' | 'update';
    versions: Array<{
        version: string;
        status: 'created' | 'updated' | 'skipped_existing';
        target_uuid?: string | null;
        assessment_result?: {
            restored: number;
            queued: number;
            skipped_empty: number;
            unmatched: number;
            ambiguous: number;
            failed: Array<Record<string, unknown>>;
        } | null;
    }>;
    summary: {
        created: number;
        updated: number;
        skipped_existing: number;
        restored_assessments: number;
        queued_assessments: number;
        unmatched_assessments: number;
        ambiguous_assessments: number;
    };
}

export interface ProjectArchiveTask {
    id: string;
    kind: 'export' | 'import_preview' | 'import_apply' | string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'not_found';
    message: string;
    progress: number;
    created_at?: string;
    updated_at?: string;
    result?: any;
    error?: string;
    log?: string[];
}

export interface ProjectArchiveSnapshot {
    filename: string;
    size: number;
    modified_at: string;
    project_name?: string | null;
    created_at?: string | null;
    version_count?: number | null;
}

export interface TMRescoreScopeOption {
    id: 'latest_only' | 'merged_versions';
    label: string;
    description: string;
}

export interface TMRescoreContext {
    enabled: boolean;
    project_name: string;
    latest_version: string;
    versions: string[];
    recommended_scope: 'latest_only' | 'merged_versions';
    scopes: TMRescoreScopeOption[];
    warnings: string[];
    llm_enrichment?: {
        available: boolean;
        status: 'available' | 'not_configured' | 'unreachable' | 'integration_disabled';
        model?: string | null;
        backend?: string | null;
        provider?: string | null;
        host_configured: boolean;
        warning?: string | null;
    };
}

export interface TMRescoreAnalysisResult {
    session_id: string;
    status: string;
    total_cves: number;
    rescored_count: number;
    avg_score_reduction: number;
    elapsed_seconds: number;
    outputs?: Record<string, string | Record<string, unknown>>;
    error?: string | null;
    session?: Record<string, any>;
    scope: 'latest_only' | 'merged_versions';
    recommended_scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    sbom_component_count: number;
    sbom_vulnerability_count: number;
    strategy_note: string;
    llm_enrichment?: {
        enabled: boolean;
        model?: string | null;
        backend?: string | null;
        provider?: string | null;
        ollama_model?: string | null;
    };
    download_urls: {
        json: string;
        vex: string;
    };
}

export interface TMRescoreAnalysisProgress {
    session_id: string;
    status: string;
    progress: number;
    step?: number | null;
    total_steps?: number | null;
    message: string;
    log?: string[];
    error?: string | null;
    created_at?: number | null;
    updated_at?: number | null;
    completed_at?: number | null;
    result?: TMRescoreAnalysisResult | null;
}

export interface TMRescoreProjectState {
    session_id: string;
    status: string;
    progress: number;
    step?: number | null;
    total_steps?: number | null;
    message: string;
    log?: string[];
    error?: string | null;
    scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    llm_enrichment?: {
        enabled: boolean;
        model?: string | null;
        backend?: string | null;
        provider?: string | null;
        ollama_model?: string | null;
    };
    analysis_options?: {
        chain_analysis: boolean;
        prioritize: boolean;
        what_if: boolean;
        mitre_enrichment: boolean;
        offline: boolean;
    };
    created_at?: number | null;
    updated_at?: number | null;
    completed_at?: number | null;
    result?: TMRescoreAnalysisResult | null;
}

export interface TMRescoreSyntheticSbomSummary {
    scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    component_count: number;
    vulnerability_count: number;
    strategy_note: string;
}

export interface TMRescoreProposalAnalysisResponse {
    title?: string | null;
    detail?: string | null;
    [key: string]: unknown;
}

export interface TMRescoreProposalAnalysis {
    detail?: string | null;
    state?: string | null;
    justification?: string | null;
    response?: Array<TMRescoreProposalAnalysisResponse | string> | null;
    [key: string]: unknown;
}

export interface TMRescoreProposal {
    vuln_id: string;
    description?: string;
    details?: string | null;
    analysis?: TMRescoreProposalAnalysis | null;
    rescored_score: number | null;
    rescored_vector: string | null;
    rescored_vector_adjusted?: boolean | null;
    original_score: number | null;
    original_vector: string | null;
    original_severity?: string | null;
    rescored_severity?: string | null;
    cwe_descriptions?: Record<string, string> | null;
    evaluations?: unknown;
    affected_refs: string[];
    session_id: string;
    scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    generated_at?: string | null;
}

export interface TMRescoreProposalSnapshot {
    project_name: string;
    session_id: string;
    scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    generated_at?: string | null;
    proposals: Record<string, TMRescoreProposal>;
}
