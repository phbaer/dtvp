import { API_PREFIX } from './apiContract'
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const csrf = document.cookie.split('; ').find(c => c.startsWith('dtvp_csrf='))?.split('=')[1]
  if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(path.startsWith('/auth/') ? path : `${API_PREFIX}${path}`, { ...options, headers, credentials: 'same-origin' })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(response.status, typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`)
  }
  return response.status === 204 ? undefined as T : response.json()
}

export const send = (value: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(value) })
