import axios from 'axios';
import type { AxiosProgressEvent } from 'axios';
import type {
    Project,
    GroupedVuln,
    AssessmentPayload,
    Statistics,
    CacheStatus,
    TMRescoreAnalysisProgress,
    TMRescoreAnalysisResult,
    TMRescoreProjectState,
    TMRescoreContext,
    TMRescoreProposalSnapshot,
    TMRescoreSyntheticSbomSummary,
    ProjectArchiveApplyResult,
    ProjectArchivePreview,
    ProjectArchiveSnapshot,
    ProjectArchiveTask,
} from '../types';
import { getRuntimeConfig } from './env';

const envApiUrl = getRuntimeConfig('DTVP_API_URL', '').replace(/\/$/, '');
const envFrontendUrl = getRuntimeConfig('DTVP_FRONTEND_URL', '').replace(/\/$/, '');
const runtimeOrigin = typeof window !== 'undefined' ? window.location.origin.replace(/\/$/, '') : '';

const BASE_URL = (envApiUrl || runtimeOrigin || envFrontendUrl).replace(/\/$/, '');
const CONTEXT_PATH = getRuntimeConfig('DTVP_CONTEXT_PATH', '/').replace(/\/$/, '');

// Ensure CONTEXT_PATH starts with / if not empty
const NORMALIZED_CONTEXT_PATH = CONTEXT_PATH ? (CONTEXT_PATH.startsWith('/') ? CONTEXT_PATH : '/' + CONTEXT_PATH) : '';

// Avoid double-appending context path if BASE_URL already includes it.
const BASE_WITH_CONTEXT = NORMALIZED_CONTEXT_PATH && BASE_URL.endsWith(NORMALIZED_CONTEXT_PATH)
    ? BASE_URL
    : BASE_URL + NORMALIZED_CONTEXT_PATH;

const API_BASE = BASE_WITH_CONTEXT + '/api';
const AUTH_BASE = BASE_URL + NORMALIZED_CONTEXT_PATH + '/auth';
const api = axios.create({
    baseURL: API_BASE,
    withCredentials: true, // For cookies
    paramsSerializer: {
        indexes: null,
    },
});

export const getProjects = async (name?: string): Promise<Project[]> => {
    // If the caller provides an empty string or only whitespace, avoid sending `?name=`.
    // Some backends (and our mock servers) treat an empty name parameter as a filters-for-nothing
    // request, which can return 422 or empty results.
    const normalized = name?.trim() || '';
    const params: Record<string, string> = {};
    if (normalized) params.name = normalized;

    const res = await api.get('/projects', { params });
    return res.data;
};

export const getStatistics = async (name?: string, cve?: string): Promise<Statistics> => {
    const res = await api.get('/statistics', { params: { name, cve } });
    return res.data;
};

export const getTaskStatistics = async (taskId: string): Promise<Statistics> => {
    const res = await api.get(`/tasks/${encodeURIComponent(taskId)}/statistics`);
    return res.data;
};

export const getVersion = async (): Promise<{ version: string, build: string }> => {
    const res = await api.get('/version');
    return res.data;
};

export const getChangelog = async (): Promise<{ content: string }> => {
    const res = await api.get('/changelog');
    return res.data;
};

export const getCacheStatus = async (): Promise<CacheStatus> => {
    const res = await api.get('/cache-status');
    return res.data;
};

export interface ProjectArchiveExportOptions {
    project_name: string;
    versions?: string[];
    refresh?: boolean;
}

export const startProjectArchiveExport = async (
    options: ProjectArchiveExportOptions,
): Promise<{ task_id: string }> => {
    const res = await api.post('/project-archives/exports', options);
    return res.data;
};

export const getProjectArchiveTask = async (
    taskId: string,
): Promise<ProjectArchiveTask> => {
    const res = await api.get(`/project-archives/tasks/${encodeURIComponent(taskId)}`);
    return res.data;
};

export const streamProjectArchiveTaskEvents = async (
    taskId: string,
    onStatus: (status: ProjectArchiveTask) => void | Promise<void>,
): Promise<void> => {
    if (typeof fetch !== 'function' || typeof TextDecoder === 'undefined') {
        throw new Error('Archive task event stream unavailable');
    }

    const response = await fetch(`${API_BASE}/project-archives/tasks/${encodeURIComponent(taskId)}/events`, {
        credentials: 'include',
    });
    if (!response.ok || !response.body) {
        throw new Error('Archive task event stream unavailable');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    const flushLines = async () => {
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            await onStatus(JSON.parse(trimmed));
        }
    };

    while (true) {
        const { done, value } = await reader.read();
        if (value) {
            buffer += decoder.decode(value, { stream: !done });
            await flushLines();
        }
        if (done) break;
    }
    buffer += decoder.decode();
    if (buffer.trim()) {
        await onStatus(JSON.parse(buffer));
    }
};

export const uploadProjectArchiveImport = async (
    file: File,
): Promise<{ task_id: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/project-archives/imports', formData);
    return res.data;
};

export const applyProjectArchiveImport = async (
    taskId: string,
    mode: 'create_missing' | 'update',
): Promise<{ task_id: string }> => {
    const res = await api.post(`/project-archives/imports/${encodeURIComponent(taskId)}/apply`, { mode });
    return res.data;
};

export const listProjectArchiveSnapshots = async (): Promise<ProjectArchiveSnapshot[]> => {
    const res = await api.get('/project-archives/snapshots');
    return res.data;
};

export const getProjectArchiveTaskDownloadUrl = (taskId: string): string =>
    `${API_BASE}/project-archives/tasks/${encodeURIComponent(taskId)}/download`;

export const getProjectArchiveSnapshotDownloadUrl = (filename: string): string =>
    `${API_BASE}/project-archives/snapshots/${encodeURIComponent(filename)}/download`;

export interface ProjectArchiveWaitOptions {
    useEventStream?: boolean;
    pollIntervalMs?: number;
}

export const waitForProjectArchiveTask = async (
    taskId: string,
    onProgress?: (status: ProjectArchiveTask) => void | Promise<void>,
    options: ProjectArchiveWaitOptions = {},
): Promise<ProjectArchiveTask> => {
    let latest: ProjectArchiveTask | null = null;
    const pollIntervalMs = Math.max(250, options.pollIntervalMs ?? 1000);
    const handleStatus = async (status: ProjectArchiveTask) => {
        latest = status;
        await onProgress?.(status);
        if (status.status === 'failed') {
            throw new Error(status.error || status.message || 'Archive task failed');
        }
    };

    if (options.useEventStream) {
        try {
            await streamProjectArchiveTaskEvents(taskId, handleStatus);
            const streamed = latest as ProjectArchiveTask | null;
            if (streamed?.status === 'completed') return streamed;
            if (streamed?.status === 'failed') throw new Error(streamed.error || streamed.message || 'Archive task failed');
            if (streamed?.status === 'not_found') throw new Error('Archive task not found');
        } catch (err: any) {
            const streamed = latest as ProjectArchiveTask | null;
            if (streamed?.status === 'failed') throw err;
            if (streamed?.status === 'not_found') throw err;
            console.warn('Archive task event stream failed; falling back to polling.', err);
        }
    }

    while (true) {
        const status = await getProjectArchiveTask(taskId);
        await handleStatus(status);
        if (status.status === 'completed') return status;
        if (status.status === 'not_found') throw new Error('Archive task not found');
        await delay(pollIntervalMs);
    }
};

export type { ProjectArchiveApplyResult, ProjectArchivePreview };

export interface TaskResponse {
    task_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    message: string;
    progress: number;
    result?: GroupedVuln[];
    result_mode?: 'full' | 'summary';
    partial_result_available?: boolean;
    partial_versions_completed?: number;
    partial_total_versions?: number;
    partial_publish_in_progress?: boolean;
    versions_completed?: number;
    versions_total?: number;
    log?: string[];
}

export interface TaskStatusOptions {
    includeResult?: boolean;
}

export interface GroupedVulnRequestOptions {
    responseMode?: 'full' | 'summary';
    onTaskId?: (taskId: string) => void;
    onPartialResultAvailable?: (taskId: string, status: TaskResponse) => void | Promise<void>;
    onTaskCompleted?: (taskId: string, status: TaskResponse) => void | Promise<void>;
    useEventStream?: boolean;
    deferResult?: boolean;
    skipResultDownload?: boolean;
    taskWindowLimit?: number;
}

export interface TaskVulnGroupListQuery {
    q?: string;
    lifecycle?: string[];
    inconsistency_reason?: string[];
    analysis?: string[];
    tag?: string;
    id?: string;
    component?: string;
    assignee?: string;
    dependency?: string[];
    versions?: string[];
    cvss_mismatch?: boolean;
    attributed_before_days?: number | null;
    attribution_mode?: 'older' | 'younger';
    tmrescore?: string[];
    tmrescore_proposal_ids?: string[];
    automatic_assessment?: string[];
    automatic_assessment_ids?: string[];
    sort?: string;
    order?: 'asc' | 'desc';
    offset?: number;
    cursor?: string | null;
    limit?: number;
}

export type BulkWorkflowFilters = Omit<
    TaskVulnGroupListQuery,
    'sort' | 'order' | 'offset' | 'cursor' | 'limit'
>;

export interface BulkWorkflowMetadata {
    id: string;
    label: string;
    description: string;
    supports_apply: boolean;
    supports_document: boolean;
    version: number;
}

export interface BulkWorkflowSummaryItem extends BulkWorkflowMetadata {
    candidate_count: number | null;
    summary: Record<string, number>;
    unavailable_reason?: string;
}

export interface BulkWorkflowSummaryResponse {
    task_id: string;
    workflows: BulkWorkflowSummaryItem[];
}

export interface BulkWorkflowPreviewItem extends Record<string, any> {
    group_id: string;
    title?: string | null;
    severity?: string | null;
}

export interface BulkWorkflowPreviewResponse {
    task_id: string;
    workflow: BulkWorkflowMetadata;
    preview_token: string;
    selectable_group_ids: string[];
    items: BulkWorkflowPreviewItem[];
    summary: Record<string, number>;
}

export interface BulkWorkflowApplyResponse {
    task_id: string;
    workflow: BulkWorkflowMetadata;
    summary: Record<string, number>;
    results: Array<Record<string, any>>;
}

export interface BulkWorkflowTaskStatus<T = unknown> {
    id: string;
    kind: string;
    source_task_id: string;
    workflow_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    message: string;
    progress: number;
    result?: T | null;
    error?: string;
}

export type BulkWorkflowProgressHandler = (
    status: BulkWorkflowTaskStatus,
) => void | Promise<void>;

export interface TaskVulnGroupListCounts {
    total: number;
    lifecycle: Record<string, number>;
    inconsistency_reason?: Record<string, number>;
    analysis: Record<string, number>;
    dependency_relationship: {
        direct: number;
        transitive: number;
        unknown: number;
    };
    cvss_version_mismatch: number;
    ids?: Record<string, number>;
    versions: Record<string, number>;
    tags: Record<string, number>;
    assignees: Record<string, number>;
    components: Record<string, number>;
    team_tags?: Record<string, { open: number; assessed: number }>;
    tmrescore?: {
        WITH_PROPOSAL: number;
        WITHOUT_PROPOSAL: number;
    };
    automatic_assessment?: {
        WITH_AUTOMATIC_ASSESSMENT: number;
        WITHOUT_AUTOMATIC_ASSESSMENT: number;
    };
    assessment_restore?: {
        WITH_RESTORE: number;
        RECOVERABLE: number;
        AMBIGUOUS: number;
        NO_HISTORY: number;
    };
    attribution_age?: number;
}

export interface TaskVulnGroupListResponse {
    items: GroupedVuln[];
    total: number;
    filtered: number;
    counts?: {
        all: TaskVulnGroupListCounts;
        filtered: TaskVulnGroupListCounts;
    };
    offset: number;
    limit: number;
    cursor?: string | null;
    next_cursor?: string | null;
    has_more?: boolean;
    sort: string;
    order: 'asc' | 'desc';
    result_mode?: 'full' | 'summary';
    source_result_mode?: 'full' | 'summary';
    partial?: boolean;
    partial_versions_completed?: number | null;
    partial_total_versions?: number | null;
    partial_publish_in_progress?: boolean | null;
    versions_completed?: number | null;
    versions_total?: number | null;
}

export const startGroupVulnTask = async (
    name: string,
    cve?: string,
    responseMode: 'full' | 'summary' = 'full',
): Promise<{ task_id: string }> => {
    const params: any = { name, response_mode: responseMode };
    if (cve) {
        params.cve = cve;
    }
    const res = await api.post('/tasks/group-vulns', null, { params });
    return res.data;
};

export const getTaskStatus = async (
    taskId: string,
    options: TaskStatusOptions = {},
): Promise<TaskResponse> => {
    if (options.includeResult === false) {
        const res = await api.get(`/tasks/${taskId}`, { params: { include_result: false } });
        return res.data;
    }
    const res = await api.get(`/tasks/${taskId}`);
    return res.data;
};

export const streamTaskEvents = async (
    taskId: string,
    onStatus: (status: TaskResponse) => void | Promise<void>,
): Promise<void> => {
    if (typeof fetch !== 'function' || typeof TextDecoder === 'undefined') {
        throw new Error('Task event stream unavailable');
    }

    const response = await fetch(`${API_BASE}/tasks/${encodeURIComponent(taskId)}/events`, {
        credentials: 'include',
    });
    if (!response.ok || !response.body) {
        throw new Error('Task event stream unavailable');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const flushLines = async () => {
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            await onStatus(JSON.parse(trimmed));
        }
    };

    while (true) {
        const { done, value } = await reader.read();
        if (value) {
            buffer += decoder.decode(value, { stream: !done });
            await flushLines();
        }
        if (done) break;
    }

    buffer += decoder.decode();
    if (buffer.trim()) {
        await onStatus(JSON.parse(buffer));
    }
};

export const getTaskVulnGroup = async (taskId: string, groupId: string): Promise<GroupedVuln> => {
    const res = await api.get(`/tasks/${encodeURIComponent(taskId)}/groups/${encodeURIComponent(groupId)}`);
    return res.data;
};

const taskGroupListParams = (query: TaskVulnGroupListQuery = {}) => {
    const params: Record<string, any> = {};
    Object.entries(query).forEach(([key, value]) => {
        if (value == null || value === '' || (Array.isArray(value) && value.length === 0)) return;
        params[key] = value;
    });
    return params;
};

export const getTaskVulnGroups = async (
    taskId: string,
    query: TaskVulnGroupListQuery = {},
): Promise<TaskVulnGroupListResponse> => {
    const params = taskGroupListParams(query);
    const res = await api.get(`/tasks/${encodeURIComponent(taskId)}/groups`, { params });
    return res.data;
};

export const bulkWorkflowFilters = (
    query: TaskVulnGroupListQuery = {},
): BulkWorkflowFilters => {
    const {
        sort: _sort,
        order: _order,
        offset: _offset,
        cursor: _cursor,
        limit: _limit,
        ...filters
    } = query;
    return filters;
};

export const getBulkWorkflowSummary = async (
    taskId: string,
    filters: BulkWorkflowFilters = {},
): Promise<BulkWorkflowSummaryResponse> => {
    const res = await api.post('/bulk-workflows/summary', {
        task_id: taskId,
        filters,
    });
    return res.data;
};

export const getBulkWorkflowTask = async <T = unknown>(
    operationId: string,
): Promise<BulkWorkflowTaskStatus<T>> => {
    const res = await api.get(`/bulk-workflows/tasks/${encodeURIComponent(operationId)}`);
    return res.data;
};

export const waitForBulkWorkflowTask = async <T>(
    operationId: string,
    onProgress?: BulkWorkflowProgressHandler,
    pollIntervalMs = 1000,
): Promise<T> => {
    const interval = Math.max(250, pollIntervalMs);
    while (true) {
        const status = await getBulkWorkflowTask<T>(operationId);
        await onProgress?.(status);
        if (status.status === 'failed') {
            throw new Error(status.error || status.message || 'Bulk workflow task failed.');
        }
        if (status.status === 'completed') {
            if (status.result == null) {
                throw new Error('Bulk workflow task completed without a result.');
            }
            return status.result;
        }
        await new Promise(resolve => window.setTimeout(resolve, interval));
    }
};

const startBulkWorkflowTask = async (
    workflowId: string,
    operation: 'preview' | 'apply' | 'document',
    payload: Record<string, unknown>,
): Promise<string> => {
    const res = await api.post(
        `/bulk-workflows/${encodeURIComponent(workflowId)}/${operation}-task`,
        payload,
    );
    return res.data.task_id;
};

export const previewBulkWorkflow = async (
    workflowId: string,
    taskId: string,
    filters: BulkWorkflowFilters = {},
    onProgress?: BulkWorkflowProgressHandler,
): Promise<BulkWorkflowPreviewResponse> => {
    const operationId = await startBulkWorkflowTask(workflowId, 'preview', {
        task_id: taskId,
        filters,
    });
    return waitForBulkWorkflowTask<BulkWorkflowPreviewResponse>(operationId, onProgress);
};

export const applyBulkWorkflow = async (
    workflowId: string,
    taskId: string,
    filters: BulkWorkflowFilters,
    groupIds: string[],
    previewToken: string,
    onProgress?: BulkWorkflowProgressHandler,
): Promise<BulkWorkflowApplyResponse> => {
    const operationId = await startBulkWorkflowTask(workflowId, 'apply', {
        task_id: taskId,
        filters,
        group_ids: groupIds,
        preview_token: previewToken,
    });
    return waitForBulkWorkflowTask<BulkWorkflowApplyResponse>(operationId, onProgress);
};

export const buildBulkWorkflowDocument = async (
    workflowId: string,
    taskId: string,
    filters: BulkWorkflowFilters,
    groupIds: string[],
    previewToken: string,
    onProgress?: BulkWorkflowProgressHandler,
): Promise<string> => {
    const operationId = await startBulkWorkflowTask(workflowId, 'document', {
        task_id: taskId,
        filters,
        group_ids: groupIds,
        preview_token: previewToken,
    });
    return waitForBulkWorkflowTask<string>(operationId, onProgress);
};

export const getTaskVulnGroupDetailsWindow = async (
    taskId: string,
    query: TaskVulnGroupListQuery = {},
): Promise<TaskVulnGroupListResponse> => {
    const params = taskGroupListParams(query);
    const res = await api.get(`/tasks/${encodeURIComponent(taskId)}/group-details`, { params });
    return res.data;
};

const normalizeTaskWindowLimit = (value: unknown): number => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return 1000;
    return Math.min(1000, Math.max(1, Math.floor(parsed)));
};

export interface DrainTaskVulnGroupOptions {
    limit?: number;
    onProgress?: (loaded: number, total: number, log?: string[]) => void;
    log?: string[];
}

export const drainTaskVulnGroups = async (
    taskId: string,
    query: TaskVulnGroupListQuery = {},
    options: DrainTaskVulnGroupOptions = {},
): Promise<GroupedVuln[]> => {
    const groups: GroupedVuln[] = [];
    let offset = 0;
    let cursor: string | null = null;
    let expectedTotal: number | null = null;
    const limit = normalizeTaskWindowLimit(options.limit);

    do {
        const pageQuery: TaskVulnGroupListQuery = {
            ...query,
            limit,
            sort: query.sort || 'id',
            order: query.order || 'asc',
        };
        if (cursor) {
            pageQuery.cursor = cursor;
        } else {
            pageQuery.offset = offset;
        }
        const window = await getTaskVulnGroups(taskId, {
            ...pageQuery,
        });
        groups.push(...(window.items || []));
        expectedTotal = window.filtered;
        cursor = window.next_cursor || null;
        if (!cursor) {
            offset += window.items?.length || 0;
        }

        if (options.onProgress) {
            const total = expectedTotal ?? groups.length;
            options.onProgress(groups.length, total, options.log);
        }

        if (!window.items || window.items.length === 0) break;
    } while (cursor || expectedTotal == null || groups.length < expectedTotal);

    return groups;
};

export const drainTaskVulnGroupDetails = async (
    taskId: string,
    query: TaskVulnGroupListQuery = {},
    options: DrainTaskVulnGroupOptions = {},
): Promise<GroupedVuln[]> => {
    const groups: GroupedVuln[] = [];
    let offset = 0;
    let cursor: string | null = null;
    let expectedTotal: number | null = null;
    const limit = normalizeTaskWindowLimit(options.limit);

    do {
        const pageQuery: TaskVulnGroupListQuery = {
            ...query,
            limit,
            sort: query.sort || 'id',
            order: query.order || 'asc',
        };
        if (cursor) {
            pageQuery.cursor = cursor;
        } else {
            pageQuery.offset = offset;
        }
        const window = await getTaskVulnGroupDetailsWindow(taskId, {
            ...pageQuery,
        });
        groups.push(...(window.items || []));
        expectedTotal = window.filtered;
        cursor = window.next_cursor || null;
        if (!cursor) {
            offset += window.items?.length || 0;
        }

        if (options.onProgress) {
            const total = expectedTotal ?? groups.length;
            options.onProgress(groups.length, total, options.log);
        }

        if (!window.items || window.items.length === 0) break;
    } while (cursor || expectedTotal == null || groups.length < expectedTotal);

    return groups;
};

export interface AssessmentRestorePreviewFinding {
    finding_uuid?: string;
    project_uuid?: string;
    project_name?: string;
    project_version?: string;
    component_uuid?: string;
    component_name?: string;
    component_version?: string;
    vulnerability_uuid?: string;
    status: string;
    reason: string;
    current_score?: number | null;
    restored_score?: number | null;
    restored_vector?: string | null;
    candidate_vectors: string[];
    source?: {
        timestamp?: string | number | null;
        commenter?: string | null;
        comment_index?: number | null;
    } | null;
}

export interface AssessmentRestorePreviewGroup {
    group_id: string;
    title?: string | null;
    severity?: string | null;
    status?: string | null;
    reason?: string | null;
    finding_count: number;
    recoverable_finding_count: number;
    findings: AssessmentRestorePreviewFinding[];
}

export interface AssessmentRestoreSummary {
    groups?: number;
    findings?: number;
    recoverable_findings?: number;
    ambiguous_findings?: number;
    no_history_findings?: number;
    attempted?: number;
    succeeded?: number;
    queued?: number;
    failed?: number;
    not_recoverable?: number;
    unchanged?: number;
    missing_identity?: number;
}

export interface AssessmentRestorePreviewResponse {
    task_id: string;
    items: AssessmentRestorePreviewGroup[];
    summary: AssessmentRestoreSummary;
}

export interface AssessmentRestoreApplyResponse {
    task_id: string;
    summary: AssessmentRestoreSummary;
    results: Array<Record<string, any>>;
}

export const previewAssessmentRestore = async (
    taskId: string,
    groupIds?: string[],
): Promise<AssessmentRestorePreviewResponse> => {
    const res = await api.post('/assessments/restore-preview', {
        task_id: taskId,
        group_ids: groupIds,
    });
    return res.data;
};

export const applyAssessmentRestore = async (
    taskId: string,
    groupIds?: string[],
): Promise<AssessmentRestoreApplyResponse> => {
    const res = await api.post('/assessments/restore-apply', {
        task_id: taskId,
        group_ids: groupIds,
    });
    return res.data;
};

export interface RescoreRuleSyncPreviewFinding {
    finding_uuid?: string;
    project_uuid?: string;
    project_name?: string;
    project_version?: string;
    component_uuid?: string;
    component_name?: string;
    component_version?: string;
    vulnerability_uuid?: string;
    state: string;
    cvss_version: string;
    status: 'ready' | 'review';
    reasons: string[];
    current_vector?: string | null;
    current_score?: number | null;
    proposed_vector?: string | null;
    proposed_score?: number | null;
}

export interface RescoreRuleSyncPreviewGroup {
    group_id: string;
    title?: string | null;
    severity?: string | null;
    finding_count: number;
    syncable_finding_count: number;
    review_finding_count: number;
    findings: RescoreRuleSyncPreviewFinding[];
}

export interface RescoreRuleSyncSummary {
    groups?: number;
    findings?: number;
    syncable_groups?: number;
    syncable_findings?: number;
    review_findings?: number;
    compliant_findings?: number;
    attempted?: number;
    succeeded?: number;
    queued?: number;
    failed?: number;
    review_required?: number;
    unchanged?: number;
}

export interface RescoreRuleSyncPreviewResponse {
    task_id: string;
    items: RescoreRuleSyncPreviewGroup[];
    summary: RescoreRuleSyncSummary;
}

export interface RescoreRuleSyncApplyResponse {
    task_id: string;
    summary: RescoreRuleSyncSummary;
    results: Array<Record<string, any>>;
}

export const previewRescoreRuleSync = async (
    taskId: string,
    groupIds?: string[],
): Promise<RescoreRuleSyncPreviewResponse> => {
    const res = await api.post('/assessments/rescore-rule-preview', {
        task_id: taskId,
        group_ids: groupIds,
    });
    return res.data;
};

export const applyRescoreRuleSync = async (
    taskId: string,
    groupIds?: string[],
): Promise<RescoreRuleSyncApplyResponse> => {
    const res = await api.post('/assessments/rescore-rule-apply', {
        task_id: taskId,
        group_ids: groupIds,
    });
    return res.data;
};

// Start a task and poll until completion
export const getGroupedVulns = async (
    name: string,
    cve?: string,
    onProgress?: (msg: string, progress: number, log?: string[]) => void,
    options: GroupedVulnRequestOptions = {},
): Promise<GroupedVuln[]> => {
    // 1. Start Task
    if (onProgress) {
        onProgress('Submitting search request...', 0);
    }
    const { task_id } = await startGroupVulnTask(name, cve, options.responseMode || 'full');
    options.onTaskId?.(task_id);

    // 2. Poll — do an immediate first poll, then continue on interval
    if (onProgress) {
        onProgress('Waiting for results...', 1);
    }

    const buildTaskFailure = (message: string) => {
        const error = new Error(message);
        (error as any).taskFailed = true;
        return error;
    };

    const handleStatus = async (status: TaskResponse): Promise<GroupedVuln[] | null> => {
        if (onProgress) {
            onProgress(status.message, status.progress, status.log);
        }

        if (status.partial_result_available && options.onPartialResultAvailable) {
            await options.onPartialResultAvailable(task_id, status);
        }

        if (status.status === 'completed') {
            if (options.onTaskCompleted) {
                await options.onTaskCompleted(task_id, status);
            }
            if (options.deferResult) {
                if (options.skipResultDownload) {
                    return [];
                }
                return drainTaskVulnGroups(
                    task_id,
                    {},
                    {
                        limit: options.taskWindowLimit,
                        log: status.log,
                        onProgress: (loaded, total, log) => {
                            const progress = total > 0 ? 90 + Math.round(Math.min(loaded / total, 1) * 10) : 100;
                            onProgress?.(`Loading vulnerability list (${loaded}/${total})...`, progress, log);
                        },
                    },
                );
            }
            return status.result || [];
        }
        if (status.status === 'failed') {
            throw buildTaskFailure(status.message);
        }
        if ((status as any).status === 'not_found') {
            throw buildTaskFailure('Task not found');
        }
        return null;
    };

    if (options.useEventStream) {
        try {
            let streamedResult: GroupedVuln[] | null = null;
            await streamTaskEvents(task_id, async (status) => {
                const result = await handleStatus(status);
                if (result) streamedResult = result;
            });
            if (streamedResult) return streamedResult;
        } catch (err: any) {
            if (err?.taskFailed) throw err;
            console.warn('Task event stream failed; falling back to polling.', err);
        }
    }

    const poll = async (): Promise<GroupedVuln[]> => {
        const status = await getTaskStatus(task_id, { includeResult: !options.deferResult });
        const result = await handleStatus(status);
        if (result) return result;
        // Continue polling if pending or running
        return new Promise((resolve, reject) => {
            setTimeout(() => poll().then(resolve, reject), 1000);
        });
    };

    return poll();
};

export const updateAssessment = async (payload: AssessmentPayload) => {
    const res = await api.post('/assessment', payload);
    return res.data;
};


export const getDependencyChains = async (
    project_uuid: string,
    component_uuid: string,
): Promise<string[]> => {
    const res = await api.get(`/project/${project_uuid}/component/${component_uuid}/dependency-chains`);
    return res.data;
};

export const getAssessmentDetails = async (instances: any[]) => {
    const res = await api.post('/assessments/details', { instances });
    return res.data;
};

export const getKnownUsers = async (): Promise<string[]> => {
    const res = await api.get('/known-users');
    return res.data;
};

export const login = (username?: string) => {
    let url = AUTH_BASE + '/login';
    if (username) {
        url += '?username=' + encodeURIComponent(username);
    }
    window.location.href = url;
};

export const logout = () => {
    window.location.href = AUTH_BASE + '/logout';
};

export const checkSession = async () => {
    try {
        await axios.get(AUTH_BASE + '/me', { withCredentials: true });
        return true;
    } catch {
        return false;
    }
};

export const getUserInfo = async (): Promise<{ username: string; role?: string }> => {
    const res = await axios.get(AUTH_BASE + '/me', { withCredentials: true });
    return res.data;
};

export const getRoles = async (): Promise<Record<string, string>> => {
    const res = await api.get('/settings/roles');
    return res.data;
};

export const uploadRoles = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/settings/roles', formData);
    return res.data;
};

export const getTeamMapping = async (): Promise<Record<string, string | string[]>> => {
    const res = await api.get('/settings/mapping');
    return res.data;
};

export const uploadTeamMapping = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/settings/mapping', formData);
    return res.data;
};

export const updateTeamMapping = async (mapping: Record<string, string | string[]>): Promise<{ status: string; message: string }> => {
    const res = await api.put('/settings/mapping', mapping);
    return res.data;
};

export const updateRoles = async (roles: Record<string, string>): Promise<{ status: string; message: string }> => {
    const res = await api.put('/settings/roles', roles);
    return res.data;
};

export const getRescoreRules = async (): Promise<any> => {
    const res = await api.get('/settings/rescore-rules');
    return res.data;
};

export const uploadRescoreRules = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/settings/rescore-rules', formData);
    return res.data;
};

export const updateRescoreRules = async (rules: Record<string, any>): Promise<{ status: string; message: string }> => {
    const res = await api.put('/settings/rescore-rules', rules);
    return res.data;
};

export const getAutoAnalysisGuidance = async (): Promise<Record<string, any>> => {
    const res = await api.get('/settings/auto-analysis-guidance');
    return res.data;
};

export const uploadAutoAnalysisGuidance = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/settings/auto-analysis-guidance', formData);
    return res.data;
};

export const updateAutoAnalysisGuidance = async (guidance: Record<string, any>): Promise<{ status: string; message: string }> => {
    const res = await api.put('/settings/auto-analysis-guidance', guidance);
    return res.data;
};

export const getTMRescoreContext = async (projectName: string): Promise<TMRescoreContext> => {
    const res = await api.get(`/projects/${encodeURIComponent(projectName)}/tmrescore/context`);
    return res.data;
};

export interface TMRescoreAnalysisOptions {
    scope: 'latest_only' | 'merged_versions';
    threatmodel: File;
    itemsCsv?: File | null;
    config?: File | null;
    countermeasures?: File | null;
    chainAnalysis?: boolean;
    prioritize?: boolean;
    whatIf?: boolean;
    enrich?: boolean;
    mitreEnrichment?: boolean;
    offline?: boolean;
}

export interface TMRescoreAnalysisProgressHandlers {
    onUploadProgress?: (event: AxiosProgressEvent) => void;
    onAnalysisProgress?: (progress: TMRescoreAnalysisProgress) => void;
    pollIntervalMs?: number;
}

export const getTMRescoreSyntheticSbomDownloadUrl = (
    projectName: string,
    scope: TMRescoreAnalysisOptions['scope'],
): string => `${API_BASE}/projects/${encodeURIComponent(projectName)}/tmrescore/sbom?scope=${encodeURIComponent(scope)}`;

export const getTMRescoreSyntheticSbomSummary = async (
    projectName: string,
    scope: TMRescoreAnalysisOptions['scope'],
): Promise<TMRescoreSyntheticSbomSummary> => {
    const res = await api.get(`/projects/${encodeURIComponent(projectName)}/tmrescore/sbom/summary`, {
        params: { scope },
    });
    return res.data;
};

export const getTMRescoreProjectState = async (
    projectName: string,
): Promise<TMRescoreProjectState> => {
    const res = await api.get(`/projects/${encodeURIComponent(projectName)}/tmrescore/state`);
    return res.data;
};

const delay = async (ms: number): Promise<void> => new Promise((resolve) => {
    window.setTimeout(resolve, ms);
});

export const getTMRescoreAnalysisProgress = async (
    sessionId: string,
): Promise<TMRescoreAnalysisProgress> => {
    const res = await api.get(`/tmrescore/sessions/${encodeURIComponent(sessionId)}/progress`);
    return res.data;
};

export const getTMRescoreAnalysisResult = async (
    sessionId: string,
): Promise<TMRescoreAnalysisResult> => {
    const res = await api.get(`/tmrescore/sessions/${encodeURIComponent(sessionId)}/results`);
    return res.data;
};

const waitForTMRescoreAnalysisCompletion = async (
    sessionId: string,
    initialProgressState: TMRescoreAnalysisProgress,
    handlers?: TMRescoreAnalysisProgressHandlers,
): Promise<TMRescoreAnalysisResult> => {
    if (initialProgressState.status === 'failed') {
        throw new Error(initialProgressState.error || initialProgressState.message || 'Threat-model analysis failed.');
    }

    let progressState = initialProgressState;
    const pollIntervalMs = handlers?.pollIntervalMs ?? 1000;
    while (!['completed', 'skeptic_gate_failed'].includes(progressState.status)) {
        await delay(pollIntervalMs);
        progressState = await getTMRescoreAnalysisProgress(sessionId);
        if (handlers?.onAnalysisProgress) {
            handlers.onAnalysisProgress(progressState);
        }
        if (progressState.status === 'failed') {
            throw new Error(progressState.error || progressState.message || 'Threat-model analysis failed.');
        }
    }

    return getTMRescoreAnalysisResult(sessionId);
};

export const resumeTMRescoreAnalysis = async (
    sessionId: string,
    state: TMRescoreAnalysisProgress | TMRescoreProjectState,
    handlers?: TMRescoreAnalysisProgressHandlers,
): Promise<TMRescoreAnalysisResult> => {
    if (handlers?.onAnalysisProgress) {
        handlers.onAnalysisProgress(state);
    }

    if (['completed', 'skeptic_gate_failed'].includes(state.status)) {
        return getTMRescoreAnalysisResult(sessionId);
    }

    return waitForTMRescoreAnalysisCompletion(sessionId, state, handlers);
};

export const runTMRescoreAnalysis = async (
    projectName: string,
    options: TMRescoreAnalysisOptions,
    handlers?: TMRescoreAnalysisProgressHandlers,
): Promise<TMRescoreAnalysisResult> => {
    const formData = new FormData();
    formData.append('scope', options.scope);
    formData.append('threatmodel', options.threatmodel);
    formData.append('chain_analysis', String(options.chainAnalysis ?? true));
    formData.append('prioritize', String(options.prioritize ?? true));
    formData.append('what_if', String(options.whatIf ?? false));
    formData.append('enrich', String(options.enrich ?? false));
    formData.append('mitre_enrichment', String(options.mitreEnrichment ?? false));
    formData.append('offline', String(options.offline ?? false));
    if (options.itemsCsv) {
        formData.append('items_csv', options.itemsCsv);
    }
    if (options.config) {
        formData.append('config', options.config);
    }
    if (options.countermeasures) {
        formData.append('countermeasures', options.countermeasures);
    }

    const res = await api.post(`/projects/${encodeURIComponent(projectName)}/tmrescore/analyze`, formData, {
        onUploadProgress: handlers?.onUploadProgress,
    });
    const initialState = res.data as TMRescoreAnalysisResult | TMRescoreAnalysisProgress;

    if ('download_urls' in initialState) {
        return initialState;
    }

    if (handlers?.onAnalysisProgress) {
        handlers.onAnalysisProgress(initialState);
    }

    if (!initialState.session_id) {
        throw new Error('TMRescore analysis did not return a session id.');
    }

    return waitForTMRescoreAnalysisCompletion(initialState.session_id, initialState, handlers);
};

export const getTMRescoreProposals = async (projectName: string): Promise<TMRescoreProposalSnapshot> => {
    const res = await api.get(`/projects/${encodeURIComponent(projectName)}/tmrescore/proposals`);
    return res.data;
};

// ── Code Analysis ────────────────────────────────────────────────────────────

export interface CodeAnalysisAssessRequest {
    vuln_id: string;
    component_name: string;
    cvss_vector?: string;
    user_guidance?: string;
    model?: string;
    llm_backend?: string;
    llm_provider?: string;
    focus_path?: string;
    dependency_paths?: string[][];
    affected_product_versions?: string[];
    debug?: boolean;
}

export interface CodeAnalysisJobSubmitted {
    job_id: string;
    status: 'pending' | 'running';
    poll_url: string;
    model?: string | null;
    llm_backend?: string | null;
    llm_provider?: string | null;
    llm?: Record<string, any> | null;
    configuration?: CodeAnalysisServiceConfiguration | null;
    backend?: CodeAnalysisBackendInformation | null;
}

export interface CodeAnalysisActiveAgentStatus {
    step: string;
    title: string;
    agent: string;
    activity: string;
    status: string;
}

export interface CodeAnalysisJobProgress {
    completed_steps: number;
    total_steps: number;
    percent: number;
    current_step?: string;
    current_title?: string;
    current_agent?: string;
    current_activity?: string;
    last_completed_step?: string;
    last_updated_at?: string;
    active_agents?: CodeAnalysisActiveAgentStatus[];
    step_statuses?: Record<string, string>;
    logs?: string[];
    log?: string[] | string;
}

export interface CodeAnalysisRepositoryConfiguration {
    workspace_dir?: string | null;
    component_count?: number | null;
    components?: string[];
    aliases?: string[];
    default_template_configured?: boolean | null;
    hot_reload?: boolean | null;
    [key: string]: any;
}

export interface CodeAnalysisServiceConfiguration {
    service_name?: string | null;
    service_version?: string | null;
    config_dir?: string | null;
    repos_config_path?: string | null;
    repositories?: CodeAnalysisRepositoryConfiguration | Record<string, any> | null;
    features?: Record<string, boolean | string | number | null>;
    [key: string]: any;
}

export interface CodeAnalysisLlmBackendInfo {
    provider?: string | null;
    backend?: string | null;
    host?: string | null;
    model?: string | null;
    healthy?: boolean | null;
    last_error?: string | null;
    supports_model_override?: boolean | null;
    [key: string]: any;
}

export interface CodeAnalysisBackendInformation {
    llm?: CodeAnalysisLlmBackendInfo | Record<string, any> | null;
    repositories?: Record<string, any> | null;
    jobs?: {
        job_store?: string;
        execution_model?: string;
        known_jobs?: number;
        status_counts?: Record<string, number>;
        max_concurrent_jobs?: number;
        running_jobs?: number;
        queued_jobs?: number;
        available_slots?: number;
        [key: string]: any;
    } | Record<string, any> | null;
    [key: string]: any;
}

export interface CodeAnalysisJobStatus {
    job_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | string;
    created_at: string;
    finished_at?: string;
    error?: string;
    progress?: CodeAnalysisJobProgress;
    request?: Record<string, any>;
    model?: string | null;
    llm_backend?: string | null;
    llm_provider?: string | null;
    llm?: Record<string, any> | null;
    logs?: Array<string | Record<string, any>>;
    configuration?: CodeAnalysisServiceConfiguration | null;
    backend?: CodeAnalysisBackendInformation | null;
}

export interface CodeAnalysisAutoSweepStatus {
    enabled: boolean;
    code_analysis_configured: boolean;
    active: boolean;
    interval_seconds: number;
    running: boolean;
    last_started_at?: string | null;
    last_finished_at?: string | null;
    last_queued_count?: number | null;
    last_error?: string | null;
    last_trigger?: string | null;
    next_run_at?: string | null;
}

export interface CodeAnalysisExternalStatus {
    health?: Record<string, any> | null;
    health_error?: string | null;
    jobs: CodeAnalysisJobStatus[];
    jobs_error?: string | null;
    configuration?: CodeAnalysisServiceConfiguration | null;
    backend?: CodeAnalysisBackendInformation | null;
    busy: boolean;
    capacity?: number | null;
    running_jobs?: number | null;
    queued_jobs?: number | null;
    available_slots?: number | null;
}

export interface CodeAnalysisDashboardStatus {
    overall_state: 'disabled' | 'unavailable' | 'idle' | 'queued' | 'running' | string;
    updated_at: string;
    configured: boolean;
    result_cache?: {
        schema_version?: string;
        path?: string;
        record_count?: number;
        max_records?: number;
        retention_days?: number;
        freshness_days?: number;
        store_guidance?: boolean;
    } | null;
    queue: {
        capacity: number;
        running_count?: number;
        available_slots?: number;
        dtvp_worker_busy: boolean;
        waiting_for_slot: boolean;
        counts_by_status: Record<string, number>;
        counts_by_source: Record<string, number>;
        active_item?: AnalysisQueueItem | null;
        active_items?: AnalysisQueueItem[];
        items: AnalysisQueueItem[];
    };
    recent_results?: CodeAnalysisResultRecord[];
    auto_sweep: CodeAnalysisAutoSweepStatus;
    external: CodeAnalysisExternalStatus;
    active_agents: CodeAnalysisActiveAgentStatus[];
    model?: string | null;
    model_source: 'queue' | 'settings' | 'health' | 'jobs' | 'result' | 'api' | 'not_reported' | string;
    llm_backend?: string | null;
    llm_backend_source: 'queue' | 'settings' | 'health' | 'jobs' | 'not_reported' | string;
    llm_provider?: string | null;
    llm_provider_source: 'queue' | 'settings' | 'health' | 'jobs' | 'not_reported' | string;
}

export interface CodeAnalysisCvssAdjustment {
    original_score: number;
    adjusted_score: number;
    original_vector?: string;
    adjusted_vector?: string;
    version?: string;
    reasons: string[];
    summary: string;
    version_context?: Record<string, any>;
    version_affected: boolean;
}

export interface CodeAnalysisStepFindings {
    step: string;
    title: string;
    status: string;
    findings: Record<string, any>;
    evidence: string[];
}

export interface CodeAnalysisVersionCheck {
    ref?: string | null;
    ref_type?: string | null;
    product_version?: string | null;
    version?: string | null;
    source?: string | null;
    affected?: boolean | string | null;
    notes?: string | null;
}

export interface CodeAnalysisVersionAnalysis extends Record<string, any> {
    detected_version?: string | null;
    version_source?: string | null;
    checked_versions?: CodeAnalysisVersionCheck[];
}

export interface CodeAnalysisAssessment {
    affected: boolean;
    verdict: string;
    confidence: string;
    exposure: string;
    analysis?: string | null;
    justification?: string | null;
    response?: string | null;
    details?: string | null;
    dependency_presence?: Record<string, any> | null;
    advisory_relevance?: Record<string, any> | null;
    version_analysis?: CodeAnalysisVersionAnalysis | null;
    researcher_view?: Record<string, any> | null;
    remediation_view?: Record<string, any> | null;
    audit_view?: Record<string, any> | null;
    ticket_text?: string | null;
    adjusted_cvss?: CodeAnalysisCvssAdjustment;
    summary: string;
    reasoning: string;
    advisory_sources?: string[];
    cwe_ids?: string[];
    cwe_descriptions?: Record<string, string>;
}

export interface CodeAnalysisComponentResult {
    component: string;
    assessment: CodeAnalysisAssessment;
    versions_checked?: string[];
}

export interface CodeAnalysisLlmMessage {
    role: string;
    content?: any;
    name?: string;
    tool_call_id?: string;
    tool_calls?: Array<Record<string, any>>;
}

export interface CodeAnalysisLlmConversationTurn {
    schema_version?: string;
    component?: string | null;
    started_at?: string | null;
    finished_at?: string | null;
    provider?: string | null;
    backend?: string | null;
    host?: string | null;
    model?: string | null;
    request?: Record<string, any> | null;
    messages?: CodeAnalysisLlmMessage[];
    response?: CodeAnalysisLlmMessage | string | null;
    usage?: Record<string, any> | null;
    status?: string | null;
    error?: string | null;
}

export interface CodeAnalysisAssessResponse {
    assessment: CodeAnalysisAssessment;
    steps: CodeAnalysisStepFindings[];
    versions_checked?: string[];
    component_results?: CodeAnalysisComponentResult[];
    llm_conversation?: CodeAnalysisLlmConversationTurn[];
}

export interface CodeAnalysisResultSummary {
    affected?: boolean | null;
    verdict?: string;
    confidence?: string;
    exposure?: string;
    analysis?: string;
    justification?: string;
    response?: string;
    summary?: string;
    reasoning?: string;
    details?: string;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    original_cvss_score?: number | null;
    original_cvss_vector?: string | null;
    adjusted_cvss_score?: number | null;
    adjusted_cvss_vector?: string | null;
    cvss_summary?: string;
    cvss_reasons?: string[];
    versions_checked?: string[];
    component_results?: Array<{
        component: string;
        verdict?: string;
        confidence?: string;
        exposure?: string;
        versions_checked?: string[];
    }>;
    step_count?: number;
}

export interface CodeAnalysisResultRecord {
    schema_version?: string;
    analysis_run_id: string;
    queue_id?: string | null;
    job_id?: string | null;
    parent_run_id?: string | null;
    parent_job_id?: string | null;
    follow_up_question?: string | null;
    user_guidance?: string | null;
    follow_up_user_guidance?: string | null;
    context_mode?: string | null;
    project_name?: string | null;
    vuln_id: string;
    component_name: string;
    source?: 'manual' | 'automatic' | 'follow-up' | string;
    submitted_by?: string | null;
    submitted_at?: string | null;
    started_at?: string | null;
    finished_at?: string | null;
    status?: string | null;
    model?: string | null;
    llm_backend?: string | null;
    llm_provider?: string | null;
    llm_metadata?: Record<string, any> | null;
    cvss_vector?: string | null;
    context_fingerprint?: string | null;
    context_summary?: Record<string, any> | null;
    summary?: CodeAnalysisResultSummary;
    compact_context?: Record<string, any>;
    result?: CodeAnalysisAssessResponse;
    recorded_at?: string | null;
}

export type CodeAnalysisAssessmentSourceKind = 'auto' | 'manual' | 'unknown';

export interface CodeAnalysisAssessmentIndexRecord {
    analysis_run_id: string;
    vuln_id: string;
    project_names: string[];
    component_names: string[];
    source_kind: CodeAnalysisAssessmentSourceKind;
}

export interface CodeAnalysisAssessmentIndexResponse {
    records: CodeAnalysisAssessmentIndexRecord[];
    summary: {
        stored_analysis_results: number;
        usable_assessment_results: number;
        indexed_assessment_results: number;
    };
}

export interface CodeAnalysisBenchmarkRequest {
    current_team?: string | null;
    current_state?: string | null;
    current_justification?: string | null;
    current_details?: string | null;
    current_cvss_score?: number | string | null;
    current_cvss_vector?: string | null;
}

export interface CodeAnalysisBenchmarkFinding {
    kind: string;
    severity: 'info' | 'warning' | 'high' | string;
    title: string;
    detail: string;
}

export interface CodeAnalysisBenchmarkComparison {
    schema_version: string;
    comparison_method?: string;
    evaluator?: {
        provider?: string;
        probabilistic?: boolean;
        available?: boolean;
        reason?: string;
        backend?: string | null;
        host?: string | null;
        model?: string | null;
        [key: string]: any;
    };
    analysis_run_id?: string | null;
    queue_id?: string | null;
    project_name?: string | null;
    vuln_id?: string | null;
    component_name?: string | null;
    compared_at: string;
    rating: {
        score: number;
        max_score: number;
        grade: string;
        label: string;
        tone: 'green' | 'cyan' | 'amber' | 'orange' | 'red' | string;
    };
    human: {
        team?: string | null;
        state: string;
        state_family: string;
        justification: string;
        cvss_score?: number | null;
        cvss_vector?: string | null;
        details_excerpt?: string;
        has_details?: boolean;
    };
    automated: {
        state: string;
        state_family: string;
        justification: string;
        cvss_score?: number | null;
        cvss_vector?: string | null;
        verdict?: string;
        confidence?: string;
        exposure?: string;
        summary_excerpt?: string;
        reasoning_excerpt?: string;
        versions_checked?: string[];
        step_count?: number;
        source?: string;
    };
    deltas: {
        state_match: boolean;
        state_family_match: boolean;
        state_distance: number;
        justification_match: boolean;
        cvss_delta?: number | null;
        cvss_vector_match?: boolean | null;
        reasoning_overlap?: number | null;
    };
    findings: CodeAnalysisBenchmarkFinding[];
    recommendation: string;
    reasoning_summary?: string | null;
}

export const codeAnalysisStartAssessment = async (req: CodeAnalysisAssessRequest): Promise<CodeAnalysisJobSubmitted> => {
    const res = await api.post('/code-analysis/assess', req);
    return res.data;
};

export const codeAnalysisGetJobStatus = async (jobId: string): Promise<CodeAnalysisJobStatus> => {
    const res = await api.get(`/code-analysis/jobs/${encodeURIComponent(jobId)}`);
    return res.data;
};

export const codeAnalysisGetJobResult = async (jobId: string): Promise<CodeAnalysisAssessResponse> => {
    const res = await api.get(`/code-analysis/jobs/${encodeURIComponent(jobId)}/result`);
    return res.data;
};

export const codeAnalysisHealth = async (): Promise<Record<string, any>> => {
    const res = await api.get('/code-analysis/health');
    return res.data;
};

export const codeAnalysisGetPrompts = async (
    params: { include_values?: boolean; system_only?: boolean } = {},
): Promise<Record<string, any>> => {
    const res = await api.get('/code-analysis/prompts', { params });
    return res.data;
};

export const codeAnalysisGetAutoSweepStatus = async (): Promise<CodeAnalysisAutoSweepStatus> => {
    const res = await api.get('/code-analysis/auto-sweep');
    return res.data;
};

export const codeAnalysisGetDashboardStatus = async (): Promise<CodeAnalysisDashboardStatus> => {
    const res = await api.get('/code-analysis/status');
    return res.data;
};

export const codeAnalysisRunAutoSweep = async (): Promise<CodeAnalysisAutoSweepStatus> => {
    const res = await api.post('/code-analysis/auto-sweep/run');
    return res.data;
};

export interface CodeAnalysisResultListParams {
    project_name?: string;
    vuln_id?: string;
    component_name?: string;
    source?: string;
    limit?: number;
    include_result?: boolean;
}

export const codeAnalysisListResults = async (
    params: CodeAnalysisResultListParams = {},
): Promise<CodeAnalysisResultRecord[]> => {
    const res = await api.get('/code-analysis/results', { params });
    return res.data;
};

export const codeAnalysisGetAssessmentIndex = async (
    projectName?: string,
): Promise<CodeAnalysisAssessmentIndexResponse> => {
    const res = await api.get('/code-analysis/assessment-index', {
        params: projectName ? { project_name: projectName } : undefined,
    });
    return res.data;
};

export const codeAnalysisGetResult = async (
    runId: string,
): Promise<CodeAnalysisResultRecord> => {
    const res = await api.get(`/code-analysis/results/${encodeURIComponent(runId)}`);
    return res.data;
};

export const codeAnalysisDeleteResult = async (
    runId: string,
): Promise<{ status: string; analysis_run_id: string }> => {
    const res = await api.delete(`/code-analysis/results/${encodeURIComponent(runId)}`);
    return res.data;
};

export const codeAnalysisCompactResult = async (
    runId: string,
): Promise<Record<string, any>> => {
    const res = await api.post(`/code-analysis/results/${encodeURIComponent(runId)}/compact`);
    return res.data;
};

export const codeAnalysisBenchmarkResult = async (
    runId: string,
    req: CodeAnalysisBenchmarkRequest,
): Promise<CodeAnalysisBenchmarkComparison> => {
    const res = await api.post(`/code-analysis/results/${encodeURIComponent(runId)}/benchmark`, req);
    return res.data;
};

export const codeAnalysisListVulnerabilityResults = async (
    projectName: string,
    vulnId: string,
    params: Omit<CodeAnalysisResultListParams, 'project_name' | 'vuln_id'> = {},
): Promise<CodeAnalysisResultRecord[]> => {
    const res = await api.get(
        `/projects/${encodeURIComponent(projectName)}/vulnerabilities/${encodeURIComponent(vulnId)}/analysis-results`,
        { params },
    );
    return res.data;
};

export const codeAnalysisRunAssessment = async (
    req: CodeAnalysisAssessRequest,
    onProgress?: (status: CodeAnalysisJobStatus) => void,
): Promise<CodeAnalysisAssessResponse> => {
    const job = await codeAnalysisStartAssessment(req);
    const jobId = job.job_id;

    const poll = async (): Promise<CodeAnalysisAssessResponse> => {
        const status = await codeAnalysisGetJobStatus(jobId);
        if (onProgress) onProgress(status);

        if (status.status === 'completed') {
            return codeAnalysisGetJobResult(jobId);
        }
        if (status.status === 'failed') {
            throw new Error(status.error || 'Code analysis failed.');
        }
        return new Promise((resolve, reject) => {
            setTimeout(() => poll().then(resolve, reject), 2000);
        });
    };

    return poll();
};

// ── Analysis Queue ───────────────────────────────────────────────────────────

export interface AnalysisQueueItem {
    queue_id: string;
    vuln_id: string;
    component_name: string;
    project_name?: string | null;
    cvss_vector?: string;
    user_guidance?: string;
    affected_product_versions?: string[];
    model?: string;
    llm_backend?: string;
    llm_provider?: string;
    llm_metadata?: Record<string, any> | null;
    parent_run_id?: string | null;
    parent_job_id?: string | null;
    follow_up_question?: string | null;
    follow_up_user_guidance?: string | null;
    context_mode?: string | null;
    context_fingerprint?: string | null;
    context_summary?: Record<string, any> | null;
    source?: 'manual' | 'automatic' | 'follow-up' | string;
    submitted_by: string;
    submitted_at: string;
    started_at?: string;
    status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
    position: number;
    job_id?: string;
    error?: string;
    result?: CodeAnalysisAssessResponse;
    finished_at?: string;
    progress?: CodeAnalysisJobProgress;
    logs?: string[];
    abort_requested?: boolean;
    abort_error?: string;
}

export const analysisQueueSubmit = async (req: {
    vuln_id: string;
    component_name: string;
    project_name?: string;
    cvss_vector?: string;
    user_guidance?: string;
    affected_product_versions?: string[];
    model?: string;
    llm_backend?: string;
    llm_provider?: string;
    source?: 'manual' | 'benchmark' | string;
}): Promise<AnalysisQueueItem> => {
    const res = await api.post('/analysis-queue/submit', req);
    return res.data;
};

export const analysisQueueSubmitFollowUp = async (req: {
    parent_run_id: string;
    question: string;
    component_name?: string;
    project_name?: string;
    cvss_vector?: string;
    user_guidance?: string;
    model?: string;
    llm_backend?: string;
    llm_provider?: string;
    context_mode?: string;
}): Promise<AnalysisQueueItem> => {
    const res = await api.post('/analysis-queue/follow-up', req);
    return res.data;
};

export const analysisQueueList = async (): Promise<AnalysisQueueItem[]> => {
    const res = await api.get('/analysis-queue');
    return res.data;
};

export const analysisQueueGet = async (queueId: string): Promise<AnalysisQueueItem> => {
    const res = await api.get(`/analysis-queue/${encodeURIComponent(queueId)}`);
    return res.data;
};

export const analysisQueueCancel = async (queueId: string): Promise<{ status: string }> => {
    const res = await api.delete(`/analysis-queue/${encodeURIComponent(queueId)}`);
    return res.data;
};

export const analysisQueueClear = async (statuses?: string[]): Promise<{ status: string; removed: number }> => {
    const res = await api.post('/analysis-queue/clear', statuses ? { statuses } : {});
    return res.data;
};

export const analysisQueueCancelQueued = async (): Promise<{ status: string; cancelled: number }> => {
    const res = await api.post('/analysis-queue/cancel-queued');
    return res.data;
};
