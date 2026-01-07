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

export const getGroupedVulns = async (name: string): Promise<GroupedVuln[]> => {
    const res = await api.get(`/projects/${name}/grouped-vulnerabilities`);
    return res.data;
};

export const updateAssessment = async (payload: AssessmentPayload) => {
    const res = await api.post('/assessment', payload);
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
