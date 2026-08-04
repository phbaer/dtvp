import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import Login from '../Login.vue'
import { login } from '../../lib/api'

const route = { query: {} as Record<string, string> }

vi.mock('vue-router', () => ({
    useRoute: () => route,
}))

// Mock the API module
vi.mock('../../lib/api', () => ({
    login: vi.fn()
}))

describe('Login.vue', () => {
    it('renders login button', () => {
        const wrapper = mount(Login)
        const button = wrapper.find('button')
        expect(button.exists()).toBe(true)
        expect(button.text()).toContain('Sign in with SSO')
    })

    it('calls login on button click', async () => {
        const wrapper = mount(Login)
        const button = wrapper.find('button')

        await button.trigger('click')

        expect(login).toHaveBeenCalled()
    })

    it('explains when an expired session caused the sign-in', () => {
        route.query = { expired: '1' }

        const wrapper = mount(Login)

        expect(wrapper.text()).toContain('Your DTVP session ended')
        route.query = {}
    })
})
