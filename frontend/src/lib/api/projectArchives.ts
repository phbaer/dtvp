import type {
    ProjectArchiveApplyResult,
    ProjectArchivePreview,
    ProjectArchiveSnapshot,
    ProjectArchiveTask,
} from '../../types'
import { API_BASE, apiClient } from './client'

export interface ProjectArchiveExportOptions {
    project_name: string
    versions?: string[]
    refresh?: boolean
}

export interface ProjectArchiveWaitOptions {
    useEventStream?: boolean
    pollIntervalMs?: number
}

export const startProjectArchiveExport = async (
    options: ProjectArchiveExportOptions,
): Promise<{ task_id: string }> => {
    const res = await apiClient.post('/project-archives/exports', options)
    return res.data
}

export const getProjectArchiveTask = async (
    taskId: string,
): Promise<ProjectArchiveTask> => {
    const res = await apiClient.get(`/project-archives/tasks/${encodeURIComponent(taskId)}`)
    return res.data
}

export const streamProjectArchiveTaskEvents = async (
    taskId: string,
    onStatus: (status: ProjectArchiveTask) => void | Promise<void>,
): Promise<void> => {
    if (typeof fetch !== 'function' || typeof TextDecoder === 'undefined') {
        throw new Error('Archive task event stream unavailable')
    }

    const response = await fetch(`${API_BASE}/project-archives/tasks/${encodeURIComponent(taskId)}/events`, {
        credentials: 'include',
    })
    if (!response.ok || !response.body) {
        throw new Error('Archive task event stream unavailable')
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    const flushLines = async () => {
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        for (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed) continue
            await onStatus(JSON.parse(trimmed))
        }
    }

    while (true) {
        const { done, value } = await reader.read()
        if (value) {
            buffer += decoder.decode(value, { stream: !done })
            await flushLines()
        }
        if (done) break
    }
    buffer += decoder.decode()
    if (buffer.trim()) {
        await onStatus(JSON.parse(buffer))
    }
}

export const uploadProjectArchiveImport = async (
    file: File,
): Promise<{ task_id: string }> => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await apiClient.post('/project-archives/imports', formData)
    return res.data
}

export const applyProjectArchiveImport = async (
    taskId: string,
    mode: 'create_missing' | 'update',
): Promise<{ task_id: string }> => {
    const res = await apiClient.post(
        `/project-archives/imports/${encodeURIComponent(taskId)}/apply`,
        { mode },
    )
    return res.data
}

export const listProjectArchiveSnapshots = async (): Promise<ProjectArchiveSnapshot[]> => {
    const res = await apiClient.get('/project-archives/snapshots')
    return res.data
}

export const getProjectArchiveTaskDownloadUrl = (taskId: string): string =>
    `${API_BASE}/project-archives/tasks/${encodeURIComponent(taskId)}/download`

export const getProjectArchiveSnapshotDownloadUrl = (filename: string): string =>
    `${API_BASE}/project-archives/snapshots/${encodeURIComponent(filename)}/download`

export const waitForProjectArchiveTask = async (
    taskId: string,
    onProgress?: (status: ProjectArchiveTask) => void | Promise<void>,
    options: ProjectArchiveWaitOptions = {},
): Promise<ProjectArchiveTask> => {
    let latest: ProjectArchiveTask | null = null
    const pollIntervalMs = Math.max(250, options.pollIntervalMs ?? 1000)
    const handleStatus = async (status: ProjectArchiveTask) => {
        latest = status
        await onProgress?.(status)
        if (status.status === 'failed') {
            throw new Error(status.error || status.message || 'Archive task failed')
        }
    }

    if (options.useEventStream) {
        try {
            await streamProjectArchiveTaskEvents(taskId, handleStatus)
            const streamed = latest as ProjectArchiveTask | null
            if (streamed?.status === 'completed') return streamed
            if (streamed?.status === 'failed') {
                throw new Error(streamed.error || streamed.message || 'Archive task failed')
            }
            if (streamed?.status === 'not_found') throw new Error('Archive task not found')
        } catch (err: any) {
            const streamed = latest as ProjectArchiveTask | null
            if (streamed?.status === 'failed' || streamed?.status === 'not_found') throw err
            console.warn('Archive task event stream failed; falling back to polling.', err)
        }
    }

    while (true) {
        const status = await getProjectArchiveTask(taskId)
        await handleStatus(status)
        if (status.status === 'completed') return status
        if (status.status === 'not_found') throw new Error('Archive task not found')
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs))
    }
}

export type { ProjectArchiveApplyResult, ProjectArchivePreview }
