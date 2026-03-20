export interface Project {
    uuid: string;
    name: string;
    version: string;
    classifier: string;
    active: boolean;
}

export type TagValue = string | { name?: string; tag?: string } | Record<string, unknown>;
export type Tags = TagValue[];

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
    analysis_details?: string;
    analysisState?: string;
    analysisDetails?: string;
    analysis_comments?: Array<{
        comment: string;
        timestamp: number;
        user?: string;
    }>;
    analysisComments?: Array<{
        comment: string;
        timestamp: number;
        user?: string;
    }>;
    is_suppressed: boolean;
    isSuppressed?: boolean;
    usage_paths?: string[];
    justification?: string;
    tags?: Tags;
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
    tags?: Tags;
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
}
