import { mount } from '@vue/test-utils'
import { defineComponent, ref } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useProjectActivityHistory } from '../useProjectActivityHistory'

const harness = () => {
    const project = ref('Product')
    const user = ref('alice')
    let history!: ReturnType<typeof useProjectActivityHistory>
    const wrapper = mount(defineComponent({
        setup() { history = useProjectActivityHistory(project, user); return {} },
        template: '<div />',
    }))
    return { history, project, user, wrapper }
}

describe('project activity history', () => {
    beforeEach(() => localStorage.clear())
    afterEach(() => vi.restoreAllMocks())

    it('keeps opened and updated events across reloads, bounded to the last 50', () => {
        const { history, wrapper } = harness()
        let time = 1000
        vi.spyOn(Date, 'now').mockImplementation(() => ++time)
        for (let index = 0; index < 60; index++) history.record({ id: `CVE-${index}`, title: 'Example' }, 'opened')
        history.record({ id: 'CVE-59' }, 'updated')
        expect(history.entries.value).toHaveLength(50)
        expect(history.entries.value.slice(0, 2).map(entry => entry.action)).toEqual(['updated', 'opened'])
        wrapper.unmount()
        const restored = harness()
        expect(restored.history.entries.value).toEqual(history.entries.value)
        restored.history.clear()
        expect(restored.history.entries.value).toEqual([])
        expect(localStorage.getItem(restored.history.key.value)).toBeNull()
        restored.wrapper.unmount()
    })

    it('isolates accounts and projects and synchronizes changes from other tabs', () => {
        const { history, project, user, wrapper } = harness()
        history.record({ id: 'CVE-1' }, 'updated')
        const key = history.key.value
        user.value = 'bob'
        expect(history.entries.value).toEqual([])
        user.value = 'alice'
        expect(history.entries.value[0]?.id).toBe('CVE-1')
        project.value = 'Another product'
        expect(history.entries.value).toEqual([])
        project.value = 'Product'
        localStorage.removeItem(key)
        window.dispatchEvent(new StorageEvent('storage', { key }))
        expect(history.entries.value).toEqual([])
        user.value = ''
        history.record({ id: 'CVE-anonymous' }, 'opened')
        expect(history.entries.value).toEqual([])
        wrapper.unmount()
    })

    it('ignores corrupt entries and retains in-memory history when storage fails', () => {
        const { history, wrapper } = harness()
        localStorage.setItem(history.key.value, JSON.stringify([{ id: 'x', title: 'x', action: 'updated', at: 1e30 }]))
        window.dispatchEvent(new StorageEvent('storage', { key: history.key.value }))
        expect(history.entries.value).toEqual([])
        localStorage.setItem(history.key.value, '{broken')
        history.record({ id: 'CVE-1' }, 'opened')
        expect(history.entries.value[0]?.id).toBe('CVE-1')
        vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Quota') })
        history.record({ id: 'CVE-2' }, 'updated')
        expect(history.entries.value[0]?.id).toBe('CVE-2')
        expect(history.persistent.value).toBe(false)
        history.clear()
        expect(history.entries.value).toEqual([])
        wrapper.unmount()
    })
})
