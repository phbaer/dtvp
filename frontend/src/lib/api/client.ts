import axios from 'axios'
import { getRuntimeConfig } from '../env'

const envApiUrl = getRuntimeConfig('DTVP_API_URL', '').replace(/\/$/, '')
const envFrontendUrl = getRuntimeConfig('DTVP_FRONTEND_URL', '').replace(/\/$/, '')
const runtimeOrigin = typeof window !== 'undefined' ? window.location.origin.replace(/\/$/, '') : ''

const baseUrl = (envApiUrl || runtimeOrigin || envFrontendUrl).replace(/\/$/, '')
const contextPath = getRuntimeConfig('DTVP_CONTEXT_PATH', '/').replace(/\/$/, '')
const normalizedContextPath = contextPath
    ? (contextPath.startsWith('/') ? contextPath : `/${contextPath}`)
    : ''
const baseWithContext = normalizedContextPath && baseUrl.endsWith(normalizedContextPath)
    ? baseUrl
    : baseUrl + normalizedContextPath

export const APP_BASE = baseWithContext
export const API_BASE = `${baseWithContext}/api`
export const AUTH_BASE = `${baseWithContext}/auth`

export const apiClient = axios.create({
    baseURL: API_BASE,
    withCredentials: true,
    paramsSerializer: {
        indexes: null,
    },
})
