import { API_PREFIX } from './apiContract'
import { ApiError } from './api'

/** Multipart transport with measured upload progress; completion still requires a receipt. */
export function knowledgeUpload<T>(path: string, body: FormData, progress: (percent: number | null, sent: boolean) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    request.open('POST', `${API_PREFIX}${path}`)
    request.withCredentials = true
    request.responseType = 'json'
    const csrf = document.cookie.split('; ').find(item => item.startsWith('dtvp_csrf='))?.split('=')[1]
    if (csrf) request.setRequestHeader('X-CSRF-Token', decodeURIComponent(csrf))
    request.upload.onprogress = event => progress(event.lengthComputable && event.total > 0 ? Math.min(100, Math.floor(event.loaded / event.total * 100)) : null, false)
    request.upload.onload = () => progress(null, true)
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) resolve(request.response as T)
      else reject(new ApiError(request.status, typeof request.response?.detail === 'string' ? request.response.detail : `Request failed (${request.status})`))
    }
    request.onerror = () => reject(new Error('Connection lost; import outcome is not confirmed.'))
    request.onabort = () => reject(new Error('Upload interrupted; import outcome is not confirmed.'))
    request.ontimeout = () => reject(new Error('Request timed out; import outcome is not confirmed.'))
    request.send(body)
  })
}
