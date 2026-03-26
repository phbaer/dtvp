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
    tags?: string[];
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
