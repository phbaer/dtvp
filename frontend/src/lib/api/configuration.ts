import { apiClient } from './client'

export const getRoles = async (): Promise<Record<string, string>> => {
    const res = await apiClient.get('/settings/roles')
    return res.data
}

export const uploadRoles = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await apiClient.post('/settings/roles', formData)
    return res.data
}

export const updateRoles = async (
    roles: Record<string, string>,
): Promise<{ status: string; message: string }> => {
    const res = await apiClient.put('/settings/roles', roles)
    return res.data
}

export const getTeamMapping = async (): Promise<Record<string, string | string[]>> => {
    const res = await apiClient.get('/settings/mapping')
    return res.data
}

export const uploadTeamMapping = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await apiClient.post('/settings/mapping', formData)
    return res.data
}

export const updateTeamMapping = async (
    mapping: Record<string, string | string[]>,
): Promise<{ status: string; message: string }> => {
    const res = await apiClient.put('/settings/mapping', mapping)
    return res.data
}

export const getRescoreRules = async (): Promise<any> => {
    const res = await apiClient.get('/settings/rescore-rules')
    return res.data
}

export const uploadRescoreRules = async (file: File): Promise<{ status: string; message: string }> => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await apiClient.post('/settings/rescore-rules', formData)
    return res.data
}

export const updateRescoreRules = async (
    rules: Record<string, any>,
): Promise<{ status: string; message: string }> => {
    const res = await apiClient.put('/settings/rescore-rules', rules)
    return res.data
}

export const getAutoAnalysisGuidance = async (): Promise<Record<string, any>> => {
    const res = await apiClient.get('/settings/auto-analysis-guidance')
    return res.data
}

export const uploadAutoAnalysisGuidance = async (
    file: File,
): Promise<{ status: string; message: string }> => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await apiClient.post('/settings/auto-analysis-guidance', formData)
    return res.data
}

export const updateAutoAnalysisGuidance = async (
    guidance: Record<string, any>,
): Promise<{ status: string; message: string }> => {
    const res = await apiClient.put('/settings/auto-analysis-guidance', guidance)
    return res.data
}
