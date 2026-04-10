import axios from 'axios';
import type { Project, GroupedVuln, AssessmentPayload, Statistics, CacheStatus } from '../types';
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

export interface TaskResponse {
    task_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    message: string;
    progress: number;
    result?: GroupedVuln[];
    log?: string[];
}

export const startGroupVulnTask = async (name: string, cve?: string): Promise<{ task_id: string }> => {
    const params: any = { name };
    if (cve) {
        params.cve = cve;
    }
    const res = await api.post('/tasks/group-vulns', null, { params });
    return res.data;
};

export const getTaskStatus = async (taskId: string): Promise<TaskResponse> => {
    const res = await api.get(`/tasks/${taskId}`);
    return res.data;
};

// Start a task and poll until completion
export const getGroupedVulns = async (name: string, cve?: string, onProgress?: (msg: string, progress: number, log?: string[]) => void): Promise<GroupedVuln[]> => {
    // 1. Start Task
    const { task_id } = await startGroupVulnTask(name, cve);

    // 2. Poll
    return new Promise((resolve, reject) => {
        const interval = setInterval(async () => {
            try {
                const status = await getTaskStatus(task_id);
                if (onProgress) {
                    onProgress(status.message, status.progress, status.log);
                }

                if (status.status === 'completed') {
                    clearInterval(interval);
                    resolve(status.result || []);
                } else if (status.status === 'failed') {
                    clearInterval(interval);
                    reject(new Error(status.message));
                }
                // Continue polling if pending or running
            } catch (e) {
                clearInterval(interval);
                reject(e);
            }
        }, 1000);
    });
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

export const getTeamMapping = async (): Promise<Record<string, string>> => {
    const res = await api.get('/settings/mapping');
    return res.data;
};

export const uploadTeamMapping = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/settings/mapping', formData);
    return res.data;
};

export const updateTeamMapping = async (mapping: Record<string, string>): Promise<{ status: string; message: string }> => {
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

