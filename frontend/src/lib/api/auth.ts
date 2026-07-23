import axios from 'axios'
import { APP_BASE, AUTH_BASE } from './client'

export const login = (username?: string) => {
    let url = `${AUTH_BASE}/login`
    if (username) {
        url += `?username=${encodeURIComponent(username)}`
    }
    window.location.href = url
}

export const logout = async () => {
    await axios.post(`${AUTH_BASE}/logout`, undefined, { withCredentials: true })
    window.location.href = `${APP_BASE}/login`
}

export const checkSession = async () => {
    try {
        await axios.get(`${AUTH_BASE}/me`, { withCredentials: true })
        return true
    } catch {
        return false
    }
}

export const getUserInfo = async (): Promise<{ username: string; role?: string }> => {
    const res = await axios.get(`${AUTH_BASE}/me`, { withCredentials: true })
    return res.data
}
