import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'

import VulnDetailModal from '../VulnDetailModal.vue'
import VulnModalTaskbar from '../VulnModalTaskbar.vue'
import { useVulnModals, type VulnModalEntry } from '../../lib/useVulnModals'
import type { GroupedVuln } from '../../types'

vi.mock('../VulnGroupCard.vue', () => ({
    default: {
        props: ['group', 'inModal'],
        template: '<section data-testid="stub-vuln-card">{{ group.id }}</section>',
    },
}))

vi.mock('lucide-vue-next', () => ({
    GripHorizontal: { template: '<span data-testid="grip-icon" />' },
    Minus: { template: '<span data-testid="minus-icon" />' },
    X: { template: '<span data-testid="x-icon" />' },
}))

const mockGroup: GroupedVuln = {
    id: 'CVE-2026-1234',
    title: 'Responsive popup test',
    severity: 'HIGH',
    cvss_score: 8.4,
    affected_versions: [],
}

const modalStore = useVulnModals()
const mountedWrappers: Array<{ unmount: () => void }> = []

const setViewport = (width: number, height: number) => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: height })
    window.dispatchEvent(new Event('resize'))
}

const buildEntry = (overrides: Partial<VulnModalEntry> = {}): VulnModalEntry => ({
    group: mockGroup,
    minimized: false,
    zIndex: 220,
    offsetX: 0,
    offsetY: 0,
    ...overrides,
})

const mountModal = (entry = buildEntry()) => {
    const wrapper = mount(VulnDetailModal, {
        attachTo: document.body,
        props: {
            id: entry.group.id,
            entry,
        },
    })
    mountedWrappers.push(wrapper)
    return wrapper
}

const styleNumber = (element: Element, property: keyof CSSStyleDeclaration): number => {
    const value = (element as HTMLElement).style[property]
    return Number.parseFloat(String(value))
}

const mouseEvent = (type: string, init: { clientX: number; clientY: number; button?: number }) => {
    const event = new Event(type, { bubbles: true, cancelable: true }) as PointerEvent
    Object.defineProperty(event, 'clientX', { value: init.clientX })
    Object.defineProperty(event, 'clientY', { value: init.clientY })
    Object.defineProperty(event, 'button', { value: init.button ?? 0 })
    return event
}

const getBodyElement = (testId: string): HTMLElement => {
    const element = document.body.querySelector(`[data-testid="${testId}"]`)
    expect(element).not.toBeNull()
    return element as HTMLElement
}

describe('VulnDetailModal', () => {
    beforeEach(() => {
        modalStore.openModals.value.clear()
        setViewport(1200, 800)
    })

    afterEach(() => {
        for (const wrapper of mountedWrappers.splice(0)) {
            wrapper.unmount()
        }
        modalStore.openModals.value.clear()
        document.body.innerHTML = ''
    })

    it('sizes and positions the desktop popup inside the viewport', async () => {
        mountModal(buildEntry({ offsetX: 48, offsetY: 48 }))
        await nextTick()

        const modal = getBodyElement('vuln-detail-modal')
        const left = styleNumber(modal, 'left')
        const top = styleNumber(modal, 'top')
        const width = styleNumber(modal, 'width')
        const height = styleNumber(modal, 'height')

        expect(left).toBeGreaterThanOrEqual(16)
        expect(top).toBeGreaterThanOrEqual(16)
        expect(width).toBeLessThanOrEqual(1100)
        expect(left + width).toBeLessThanOrEqual(1184)
        expect(top + height).toBeLessThanOrEqual(784)
        expect(getBodyElement('vuln-detail-modal-titlebar').classList).toContain('cursor-grab')
    })

    it('uses a compact near-fullscreen popup on narrow viewports', async () => {
        setViewport(500, 640)
        mountModal(buildEntry({ offsetX: 140, offsetY: 140 }))
        await nextTick()

        const modal = getBodyElement('vuln-detail-modal')

        expect(styleNumber(modal, 'left')).toBe(8)
        expect(styleNumber(modal, 'top')).toBe(8)
        expect(styleNumber(modal, 'width')).toBe(484)
        expect(styleNumber(modal, 'height')).toBe(624)
        expect(getBodyElement('vuln-detail-modal-titlebar').classList).toContain('cursor-default')
    })

    it('reserves bottom space when minimized dialogs are visible', async () => {
        setViewport(500, 640)
        const minimizedGroup = { ...mockGroup, id: 'CVE-2026-5678' }
        modalStore.openModal(minimizedGroup)
        modalStore.minimizeModal(minimizedGroup.id)

        mountModal()
        await nextTick()

        const modal = getBodyElement('vuln-detail-modal')
        expect(styleNumber(modal, 'height')).toBe(572)
    })

    it('clamps dragging so the popup cannot be moved off-screen', async () => {
        setViewport(900, 600)
        mountModal()
        await nextTick()

        const modal = getBodyElement('vuln-detail-modal')
        const titlebar = getBodyElement('vuln-detail-modal-titlebar')
        const initialLeft = styleNumber(modal, 'left')
        const initialTop = styleNumber(modal, 'top')
        const width = styleNumber(modal, 'width')
        const height = styleNumber(modal, 'height')

        titlebar.dispatchEvent(mouseEvent('mousedown', {
            clientX: initialLeft + 20,
            clientY: initialTop + 12,
            button: 0,
        }))
        await nextTick()
        window.dispatchEvent(mouseEvent('mousemove', {
            clientX: 9999,
            clientY: 9999,
        }))
        await nextTick()

        expect(styleNumber(modal, 'left')).toBe(900 - width - 16)
        expect(styleNumber(modal, 'top')).toBe(600 - height - 16)

        window.dispatchEvent(mouseEvent('mouseup', {
            clientX: 9999,
            clientY: 9999,
        }))
    })

    it('recenters into compact bounds after a viewport resize', async () => {
        setViewport(1280, 820)
        mountModal(buildEntry({ offsetX: 120, offsetY: 120 }))
        await nextTick()

        setViewport(640, 500)
        await nextTick()

        const modal = getBodyElement('vuln-detail-modal')
        expect(styleNumber(modal, 'left')).toBe(8)
        expect(styleNumber(modal, 'top')).toBe(8)
        expect(styleNumber(modal, 'width')).toBe(624)
        expect(styleNumber(modal, 'height')).toBe(484)
    })
})

describe('VulnModalTaskbar', () => {
    beforeEach(() => {
        modalStore.openModals.value.clear()
    })

    afterEach(() => {
        for (const wrapper of mountedWrappers.splice(0)) {
            wrapper.unmount()
        }
        modalStore.openModals.value.clear()
        document.body.innerHTML = ''
    })

    it('wraps minimized vulnerability tabs within the viewport', async () => {
        modalStore.openModal(mockGroup)
        modalStore.minimizeModal(mockGroup.id)
        const wrapper = mount(VulnModalTaskbar, {
            attachTo: document.body,
        })
        mountedWrappers.push(wrapper)
        await nextTick()

        const taskbar = getBodyElement('vuln-modal-taskbar')
        const tab = document.body.querySelector('.pointer-events-auto')
        expect(tab).not.toBeNull()

        expect(taskbar.classList).toContain('flex-wrap')
        expect(taskbar.classList).toContain('overflow-y-auto')
        expect(tab!.classList).toContain('min-w-0')
        expect(tab!.classList).toContain('flex-[1_1_9rem]')
    })
})
