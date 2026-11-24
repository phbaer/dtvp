import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { ref } from 'vue'
import VulnDetailInspector from '../VulnDetailInspector.vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

vi.mock('../../lib/api', () => ({
    getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
    getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
    updateAssessment: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue({ paths: [], total: 0, limit: 10, offset: 0 }),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getKnownUsers: vi.fn(() => Promise.resolve([])),
}))

vi.mock('../DependencyChainViewer.vue', () => ({
    default: { template: '<div />', props: ['projectUuid', 'componentUuid', 'projectName'] },
}))

const group = {
    id: 'CVE-2023-1234',
    title: 'Test Vulnerability',
    description: 'A bad vulnerability',
    severity: 'HIGH',
    cvss: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    tags: ['Security'],
    aliases: [],
    affected_versions: [{
        project_name: 'App1',
        project_version: '1.0',
        project_uuid: 'p1',
        components: [{
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            component_name: 'lib',
            component_version: '1.0',
            component_uuid: 'c1',
            vulnerability_uuid: 'v1',
            finding_uuid: 'f1',
            analysis_state: 'NOT_SET',
            analysis_details: '',
            is_suppressed: false,
            analysis_comments: [],
            tags: ['Security'],
            is_direct_dependency: false,
        }],
    }],
}

const ASIDE = '[data-testid="vuln-detail-inspector"]'
const aside = () => document.querySelector<HTMLElement>(ASIDE)!
const toggle = () => document.querySelector<HTMLButtonElement>('[data-testid="workspace-toggle"]')!
const pressEscape = (target: HTMLElement) => {
    const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    target.dispatchEvent(event)
    return event
}

describe('VulnDetailInspector assessment workspace', () => {
    let wrapper: VueWrapper<any> | null = null
    const originalScrollTo = HTMLElement.prototype.scrollTo
    const originalScrollIntoView = HTMLElement.prototype.scrollIntoView

    const mountInspector = async (props: Record<string, unknown> = {}, attrs: Record<string, unknown> = {}) => {
        wrapper = mount(VulnDetailInspector, {
            props: { group: group as any, workspaceAvailable: true, ...props },
            attrs,
            attachTo: document.body,
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await flushPromises()
        return wrapper
    }

    const openWorkspace = async () => {
        toggle().click()
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
    }

    beforeEach(() => {
        HTMLElement.prototype.scrollTo = vi.fn() as any
        HTMLElement.prototype.scrollIntoView = vi.fn() as any
    })

    afterEach(() => {
        wrapper?.unmount()
        wrapper = null
        document.body.innerHTML = ''
        HTMLElement.prototype.scrollTo = originalScrollTo
        HTMLElement.prototype.scrollIntoView = originalScrollIntoView
    })

    it('moves the same card to a full-screen dialog and back', async () => {
        const inspector = await mountInspector({}, { class: 'h-full' })
        const card = inspector.findComponent(VulnGroupCard).vm.$

        expect(aside().dataset.workspace).toBe('closed')
        expect(aside().parentElement).toBe(inspector.element.parentElement)
        expect(aside().classList.contains('h-full')).toBe(true)
        expect(aside().getAttribute('role')).toBeNull()

        const textarea = () => document.querySelector<HTMLTextAreaElement>('#analysis-details-textarea')!
        textarea().value = 'Reachable through the parser.'
        textarea().dispatchEvent(new Event('input'))
        await flushPromises()

        await openWorkspace()
        expect(aside().parentElement).toBe(document.body)
        expect(aside().classList.contains('fixed')).toBe(true)
        expect(aside().getAttribute('role')).toBe('dialog')
        expect(aside().getAttribute('aria-modal')).toBe('true')
        expect(aside().getAttribute('aria-label')).toBe('Assessment workspace for CVE-2023-1234')
        // The attribute from the host still lands on the aside.
        expect(aside().classList.contains('h-full')).toBe(true)
        // No remount: the same instance and the unsaved text.
        expect(inspector.findComponent(VulnGroupCard).vm.$).toBe(card)
        expect(textarea().value).toBe('Reachable through the parser.')
        expect(inspector.findComponent(VulnGroupCard).props('workspace')).toBe(true)

        toggle().click()
        await flushPromises()
        expect(aside().dataset.workspace).toBe('closed')
        expect(aside().parentElement).not.toBe(document.body)
        expect(inspector.findComponent(VulnGroupCard).vm.$).toBe(card)
        expect(textarea().value).toBe('Reachable through the parser.')
    })

    it('focuses the assessment heading on entry and the toggle on exit', async () => {
        await mountInspector()
        await openWorkspace()
        expect(document.activeElement?.getAttribute('data-testid')).toBe('workspace-assessment-heading')

        toggle().click()
        await flushPromises()
        expect(document.activeElement).toBe(toggle())
    })

    it('leaves the workspace on Esc without closing the details', async () => {
        const inspector = await mountInspector()
        await openWorkspace()

        pressEscape(document.querySelector<HTMLElement>('[data-testid="workspace-assessment-heading"]')!)
        await flushPromises()

        expect(aside().dataset.workspace).toBe('closed')
        expect(inspector.emitted('close')).toBeUndefined()
        expect(document.activeElement).toBe(toggle())
        expect((inspector.findComponent(VulnGroupCard).vm as any).activeDetailTab).toBe('review')
    })

    it('keeps the workspace on Esc while a menu or modal is open', async () => {
        const inspector = await mountInspector()
        await openWorkspace()
        const heading = document.querySelector<HTMLElement>('[data-testid="workspace-assessment-heading"]')!

        const menu = document.createElement('div')
        menu.dataset.testid = 'custom-select-menu'
        document.body.appendChild(menu)
        pressEscape(heading)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
        menu.remove()

        const card = inspector.findComponent(VulnGroupCard).vm as any
        card.showClearModal = true
        await flushPromises()
        expect(card.hasOpenOverlay()).toBe(true)
        pressEscape(heading)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
        card.showClearModal = false
        await flushPromises()

        // The first Esc closes the More menu, a second leaves the workspace.
        card.showMoreMenu = true
        await flushPromises()
        pressEscape(heading)
        await flushPromises()
        expect(card.showMoreMenu).toBe(false)
        expect(aside().dataset.workspace).toBe('open')
        pressEscape(heading)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('closed')
    })

    it('keeps the workspace on Esc in an editable element', async () => {
        await mountInspector()
        await openWorkspace()

        pressEscape(document.querySelector<HTMLTextAreaElement>('#analysis-details-textarea')!)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')

        const input = document.createElement('input')
        aside().appendChild(input)
        pressEscape(input)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
        input.remove()

        const select = document.createElement('select')
        aside().appendChild(select)
        pressEscape(select)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
        select.remove()

        const editable = document.createElement('div')
        editable.setAttribute('contenteditable', 'true')
        const inner = document.createElement('span')
        editable.appendChild(inner)
        aside().appendChild(editable)
        pressEscape(inner)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
        editable.remove()

        const handled = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
        handled.preventDefault()
        document.querySelector<HTMLElement>('[data-testid="workspace-assessment-heading"]')!.dispatchEvent(handled)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('open')
    })

    it('closes the workspace when the viewport becomes too narrow', async () => {
        const inspector = await mountInspector()
        await openWorkspace()

        await inspector.setProps({ workspaceAvailable: false })
        await flushPromises()

        expect(aside().dataset.workspace).toBe('closed')
        expect(document.querySelector('[data-testid="workspace-toggle"]')).toBeNull()
        expect(inspector.findComponent(VulnGroupCard).props('workspace')).toBe(false)
        // The toggle is gone, so focus lands on the Assessment tab, not the body.
        expect(document.activeElement?.id).toBe('vuln-CVE-2023-1234-detail-tab-review')
    })

    it('leaves the workspace on Esc when focus fell to the body', async () => {
        await mountInspector()
        await openWorkspace()
        // A click on plain text, or a closed teleported menu, drops focus to the body.
        ;(document.activeElement as HTMLElement).blur()
        expect(document.activeElement).toBe(document.body)

        pressEscape(document.body)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('closed')
    })

    it('keeps focus in the workspace when a click lands on plain text', async () => {
        await mountInspector()
        await openWorkspace()
        expect(aside().getAttribute('tabindex')).toBe('-1')

        toggle().click()
        await flushPromises()
        expect(aside().hasAttribute('tabindex')).toBe(false)
    })

    it('leaves the workspace on Esc on a checkbox or a button input', async () => {
        await mountInspector()
        for (const type of ['checkbox', 'radio', 'button']) {
            await openWorkspace()
            const input = document.createElement('input')
            input.type = type
            aside().appendChild(input)
            pressEscape(input)
            await flushPromises()
            expect(aside().dataset.workspace, type).toBe('closed')
            input.remove()
        }
    })

    it('stops listening for Esc once the workspace is closed', async () => {
        const inspector = await mountInspector()
        await openWorkspace()
        toggle().click()
        await flushPromises()

        pressEscape(document.body)
        await flushPromises()
        expect(aside().dataset.workspace).toBe('closed')
        expect(inspector.emitted('close')).toBeUndefined()
    })

    describe('Tab', () => {
        const originalGetClientRects = Element.prototype.getClientRects
        beforeEach(() => {
            // jsdom has no layout; treat every element as rendered.
            Element.prototype.getClientRects = function () { return [{}] as unknown as DOMRectList }
        })
        afterEach(() => {
            Element.prototype.getClientRects = originalGetClientRects
        })

        const pressTab = (shiftKey = false) => {
            const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey, bubbles: true, cancelable: true })
            ;(document.activeElement ?? document.body).dispatchEvent(event)
            return event
        }
        const focusable = () => [...aside().querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        )].filter(element => element.tabIndex !== -1)

        it('wraps inside the workspace and brings focus back from outside', async () => {
            await mountInspector()
            await openWorkspace()
            const elements = focusable()
            const first = elements[0]!
            const last = elements[elements.length - 1]!

            last.focus()
            expect(pressTab().defaultPrevented).toBe(true)
            expect(document.activeElement).toBe(first)

            expect(pressTab(true).defaultPrevented).toBe(true)
            expect(document.activeElement).toBe(last)

            const outside = document.createElement('button')
            document.body.insertBefore(outside, document.body.firstChild)
            outside.focus()
            expect(pressTab().defaultPrevented).toBe(true)
            expect(document.activeElement).toBe(first)
            outside.remove()

            // In between, Tab is left to the browser.
            first.focus()
            expect(pressTab().defaultPrevented).toBe(false)
        })

        it('leaves Tab alone while the workspace is closed', async () => {
            await mountInspector()
            const last = focusable().at(-1)!
            last.focus()
            expect(pressTab().defaultPrevented).toBe(false)
        })
    })

    it('delegates the draft guard to the card in both layouts', async () => {
        const inspector = await mountInspector()
        // Nothing unsaved: leaving is fine.
        await expect(inspector.vm.confirmApplyDraftBeforeLeave()).resolves.toBe(true)

        const card = inspector.findComponent(VulnGroupCard).vm as any
        card.formTouched = true
        await flushPromises()
        const closed = inspector.vm.confirmApplyDraftBeforeLeave()
        await flushPromises()
        expect(document.body.textContent).toContain('Save this assessment before leaving?')
        ;[...document.querySelectorAll('button')].find(button => button.textContent?.trim() === 'Stay')!.click()
        await expect(closed).resolves.toBe(false)

        await openWorkspace()
        const open = inspector.vm.confirmApplyDraftBeforeLeave()
        await flushPromises()
        expect(document.body.textContent).toContain('Save this assessment before leaving?')
        ;[...document.querySelectorAll('button')].find(button => button.textContent?.trim() === 'Stay')!.click()
        await expect(open).resolves.toBe(false)
        expect(aside().dataset.workspace).toBe('open')
    })
})
