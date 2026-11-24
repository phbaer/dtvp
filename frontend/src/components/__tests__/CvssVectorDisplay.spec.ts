import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import CvssVectorDisplay from '../CvssVectorDisplay.vue'

const ORIGINAL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const RESCORED = `${ORIGINAL}/MPR:L`

describe('CvssVectorDisplay', () => {
    const mountDisplay = () => mount(CvssVectorDisplay, {
        props: {
            vectors: [
                { vector: ORIGINAL, label: 'Original', theme: 'gray' },
                { vector: RESCORED, label: 'Rescored', theme: 'purple' },
            ],
        },
    })

    it('wraps instead of scrolling or clipping', () => {
        const wrapper = mountDisplay()
        const root = wrapper.get('[data-testid="cvss-vector-display"]')
        expect(root.classes()).not.toContain('overflow-x-auto')
        expect(root.classes()).not.toContain('overflow-hidden')
        // A long vector breaks inside its line; the sections wrap as a whole.
        const rows = wrapper.findAll('[data-testid="cvss-vector-row"]')
        expect(rows).toHaveLength(2)
        expect(rows[1].text()).toContain(RESCORED)
        const text = rows[1].get('[data-testid="cvss-vector-text"]')
        expect(text.text()).toBe(RESCORED)
        expect(text.findAll('wbr').length).toBe(RESCORED.split('/').length)
        expect(rows[1].text()).toContain('env.')
        expect(wrapper.get('[data-testid="cvss-metric-sections"]').classes()).toContain('flex-wrap')
    })

    it('shows only the sections and metrics the vectors have, each row labelled', () => {
        const wrapper = mountDisplay()
        const sections = wrapper.findAll('[data-testid="cvss-metric-section"]')
        expect(sections.map(section => section.get('caption').text())).toEqual(['Exploitability', 'Impact / Vuln. System'])
        const exploitability = sections[0]
        expect(exploitability.findAll('thead th[scope="col"]').map(cell => cell.text())).toEqual(['AV', 'AC', 'PR', 'UI'])
        expect(exploitability.findAll('tbody th').map(cell => cell.text())).toEqual(['Original', 'Rescored'])
        // The rescored row takes the modified privileges.
        const rescoredCells = exploitability.findAll('tbody tr')[1].findAll('td')
        expect(rescoredCells.map(cell => cell.text())).toEqual(['N', 'L', 'L', 'N'])
        expect(rescoredCells[2].get('div').attributes('title')).toBe('Rescored: Privileges Required: Low')
        expect(sections[1].findAll('thead th[scope="col"]').map(cell => cell.text())).toEqual(['S', 'C', 'I', 'A'])
    })

    it('needs no row labels for a single vector', () => {
        const wrapper = mount(CvssVectorDisplay, { props: { vectors: [{ vector: ORIGINAL, label: 'Original', theme: 'gray' }] } })
        expect(wrapper.find('[data-testid="cvss-metric-section"] tbody th').exists()).toBe(false)
        expect(wrapper.get('[data-testid="cvss-vector-row"]').text()).toContain('9.8 CRITICAL')
    })
})
