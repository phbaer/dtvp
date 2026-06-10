export interface Project {
    uuid: string;
    name: string;
    version: string;
    classifier: string;
    active: boolean;
}

export type TagValue = string | { name?: string; tag?: string } | null;
export type Tags = Array<string | TagValue>;

export interface Instance {
    project_name: string;
    project_version: string;
    project_uuid: string;
    component_name: string;
    component_version: string;
    component_uuid: string;
    vulnerability_uuid: string;
    finding_uuid: string;
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
}


export interface AffectedVersion {
    project_name: string;
    project_version: string;
    project_uuid: string;
    components: Instance[];
}

export interface GroupedVuln {
    id: string; // CVE/VulnID
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
    affected_versions: AffectedVersion[];
}

export interface AssessmentPayload {
    instances: Instance[];
    state: string;
    details: string;
    comment?: string;
    justification?: string;
    suppressed: boolean;
    team?: string;
    assigned?: string[];
    original_analysis?: Record<string, any>;
    force?: boolean;
    comparison_mode?: 'MERGE' | 'REPLACE';
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
    fully_cached: boolean;
    last_refreshed_at: string | null;
    projects: number;
    active_projects: number;
    cached_findings: number;
    cached_boms: number;
    cached_analyses: number;
    pending_updates: number;
}

export interface TMRescoreScopeOption {
    id: 'latest_only' | 'merged_versions';
    label: string;
    description: string;
}

export interface TMRescoreContext {
    enabled: boolean;
    wizard_url?: string | null;
    project_name: string;
    latest_version: string;
    versions: string[];
    recommended_scope: 'latest_only' | 'merged_versions';
    scopes: TMRescoreScopeOption[];
    warnings: string[];
    llm_enrichment?: {
        available: boolean;
        status: 'available' | 'not_configured' | 'unreachable' | 'integration_disabled';
        default_model: string;
        host_configured: boolean;
        warning?: string | null;
    };
}

export interface VScorerWizardValidationSummary {
    errors?: number;
    warnings?: number;
    infos?: number;
}

export interface VScorerValidationReport {
    artefact?: string;
    ok?: boolean;
    file?: string;
    model_name?: string;
    parsed_at?: number;
    counts?: Record<string, any>;
    grade?: string;
    grade_rationale?: string;
    findings?: Array<Record<string, any>>;
    family_labels?: Record<string, string>;
    summary?: VScorerWizardValidationSummary;
    [key: string]: any;
}

export interface VScorerValidationReports {
    reports?: VScorerValidationReport[];
    summary?: VScorerWizardValidationSummary;
    [key: string]: any;
}

export interface VScorerThreatModelEditorIssue {
    issue_id?: string;
    severity?: string;
    title?: string;
    message?: string;
    target_type?: string;
    target_id?: string;
    editable?: boolean;
    kept?: boolean;
    note?: string;
    [key: string]: any;
}

export interface VScorerThreatModelEditorState {
    ok?: boolean;
    model_name?: string;
    summary?: Record<string, any>;
    issues?: VScorerThreatModelEditorIssue[];
    [key: string]: any;
}

export interface VScorerThreatModelEditorPatch {
    issue_id: string;
    action?: string;
    target_type?: string | null;
    target_id?: string | null;
    values?: Record<string, any>;
    note?: string;
}

export interface VScorerWizardContext {
    session?: Record<string, any>;
    files?: Record<string, any>;
    missing_inputs?: Record<string, string[]>;
    validation?: VScorerValidationReports | null;
    threat_model?: {
        ok?: boolean;
        elements?: Array<Record<string, any>>;
        boundaries?: Array<Record<string, any>>;
        [key: string]: any;
    } | null;
    editor?: VScorerThreatModelEditorState | null;
    threat_model_editor?: VScorerThreatModelEditorState | null;
    links?: Record<string, string>;
    [key: string]: any;
}

export type VScorerRuleTypeCatalog = Record<string, Array<Record<string, any>>> | Array<Record<string, any>>;

export interface VScorerWizardCatalogs {
    app_info?: Record<string, any>;
    rescoring_rule_types?: VScorerRuleTypeCatalog;
    attack_mitigations?: Array<Record<string, any>>;
    archetypes?: Array<Record<string, any>>;
    [key: string]: any;
}

export interface TMRescoreAnalysisResult {
    session_id: string;
    status: string;
    total_cves: number;
    rescored_count: number;
    avg_score_reduction: number;
    elapsed_seconds: number;
    outputs?: Record<string, any>;
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
    message: string;
    log?: string[];
    error?: string | null;
    created_at?: number | null;
    updated_at?: number | null;
    completed_at?: number | null;
    result?: TMRescoreAnalysisResult | null;
    wizard_url?: string | null;
    wizard_context?: VScorerWizardContext | null;
    wizard_catalogs?: VScorerWizardCatalogs | null;
}

export interface TMRescoreProjectState {
    session_id: string;
    status: string;
    progress: number;
    message: string;
    log?: string[];
    error?: string | null;
    scope: 'latest_only' | 'merged_versions';
    latest_version: string;
    analyzed_versions: string[];
    llm_enrichment?: {
        enabled: boolean;
        ollama_model?: string | null;
    };
    created_at?: number | null;
    updated_at?: number | null;
    completed_at?: number | null;
    result?: TMRescoreAnalysisResult | null;
    wizard_url?: string | null;
    wizard_context?: VScorerWizardContext | null;
    wizard_catalogs?: VScorerWizardCatalogs | null;
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

export type VScorerScopeOption = TMRescoreScopeOption;
export type VScorerContext = TMRescoreContext;
export type VScorerAnalysisResult = TMRescoreAnalysisResult;
export type VScorerAnalysisProgress = TMRescoreAnalysisProgress;
export type VScorerProjectState = TMRescoreProjectState;
export type VScorerSyntheticSbomSummary = TMRescoreSyntheticSbomSummary;
export type VScorerProposalAnalysisResponse = TMRescoreProposalAnalysisResponse;
export type VScorerProposalAnalysis = TMRescoreProposalAnalysis;
export type VScorerProposal = TMRescoreProposal;
export type VScorerProposalSnapshot = TMRescoreProposalSnapshot;
