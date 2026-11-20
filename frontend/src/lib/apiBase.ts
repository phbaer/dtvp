import { getRuntimeConfig } from './env'

// The backend's base URLs. Kept apart from api.ts so modules that only need
// a URL (the live event stream) do not load the HTTP client with it.
const envApiUrl = getRuntimeConfig('DTVP_API_URL', '').replace(/\/$/, '')
const envFrontendUrl = getRuntimeConfig('DTVP_FRONTEND_URL', '').replace(/\/$/, '')
const runtimeOrigin = typeof window !== 'undefined' ? window.location.origin.replace(/\/$/, '') : ''

export const BASE_URL = (envApiUrl || runtimeOrigin || envFrontendUrl).replace(/\/$/, '')
const CONTEXT_PATH = getRuntimeConfig('DTVP_CONTEXT_PATH', '/').replace(/\/$/, '')

// Ensure CONTEXT_PATH starts with / if not empty
export const NORMALIZED_CONTEXT_PATH = CONTEXT_PATH ? (CONTEXT_PATH.startsWith('/') ? CONTEXT_PATH : '/' + CONTEXT_PATH) : ''

// Avoid double-appending context path if BASE_URL already includes it.
export const BASE_WITH_CONTEXT = NORMALIZED_CONTEXT_PATH && BASE_URL.endsWith(NORMALIZED_CONTEXT_PATH)
    ? BASE_URL
    : BASE_URL + NORMALIZED_CONTEXT_PATH

export const API_BASE = BASE_WITH_CONTEXT + '/api'
export const AUTH_BASE = BASE_URL + NORMALIZED_CONTEXT_PATH + '/auth'
