import axios from 'axios';
import type { Project, GroupedVuln, AssessmentPayload } from '../types';
import { getRuntimeConfig } from './env';

const BASE_URL = getRuntimeConfig('DTVP_FRONTEND_URL', window.location.origin).replace(/\/$/, '');
const CONTEXT_PATH = getRuntimeConfig('DTVP_CONTEXT_PATH', '/').replace(/\/$/, '');

// Ensure CONTEXT_PATH starts with / if not empty
const NORMALIZED_CONTEXT_PATH = CONTEXT_PATH ? (CONTEXT_PATH.startsWith('/') ? CONTEXT_PATH : '/' + CONTEXT_PATH) : '';

const API_BASE = BASE_URL + NORMALIZED_CONTEXT_PATH + '/api';
const AUTH_BASE = BASE_URL + NORMALIZED_CONTEXT_PATH + '/auth';

const api = axios.create({
    baseURL: API_BASE,
    withCredentials: true, // For cookies
});

export const getProjects = async (name: string): Promise<Project[]> => {
    const res = await api.get('/projects', { params: { name } });
    return res.data;
};

export const getVersion = async (): Promise<{ version: string, build: string }> => {
    const res = await api.get('/version');
    return res.data;
};

export interface TaskResponse {
    task_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    message: string;
    progress: number;
    result?: GroupedVuln[];
}

export const startGroupVulnTask = async (name: string): Promise<{ task_id: string }> => {
    const res = await api.post('/tasks/group-vulns', null, { params: { name } });
    return res.data;
};

export const getTaskStatus = async (taskId: string): Promise<TaskResponse> => {
    const res = await api.get(`/tasks/${taskId}`);
    return res.data;
};

// Start a task and poll until completion
export const getGroupedVulns = async (name: string, onProgress?: (msg: string, progress: number) => void): Promise<GroupedVuln[]> => {
    // 1. Start Task
    const { task_id } = await startGroupVulnTask(name);

    // 2. Poll
    return new Promise((resolve, reject) => {
        const interval = setInterval(async () => {
            try {
                const status = await getTaskStatus(task_id);
                if (onProgress) {
                    onProgress(status.message, status.progress);
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

export const login = () => {
    window.location.href = AUTH_BASE + '/login';
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
