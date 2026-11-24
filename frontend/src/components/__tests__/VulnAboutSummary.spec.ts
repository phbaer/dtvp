import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnAboutSummary from '../VulnAboutSummary.vue'

const mountSummary = (props: Record<string, unknown> = {}) => mount(VulnAboutSummary, {
    props: { vulnId: 'CVE-1', components: [], projectVersions: [], links: [], ...props },
})

describe('VulnAboutSummary', () => {
    it('describes the attack conditions of CVSS 2, 3 and 4 vectors in words', () => {
        const attack = (cvssVector: string) => mountSummary({ cvssVector }).find('[data-testid="vuln-about-attack"]')
        expect(attack('AV:N/AC:M/Au:S/C:P/I:P/A:P').text()).toContain('network, medium complexity, single authentication')
        expect(attack('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H').text())
            .toContain('local, high complexity, high privileges, user interaction')
        expect(attack('CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').text())
            .toContain('adjacent network, low complexity, attack requirements present, low privileges, passive user interaction')
        expect(attack('').exists()).toBe(false)
    })

    it('shows no title equal to the id, a placeholder without description, and no expander for short text', () => {
        const wrapper = mountSummary({ title: 'CVE-1', description: '' })
        expect(wrapper.find('[data-testid="vuln-about-title"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="vuln-about-description"]').text()).toBe('No description available.')
        expect(wrapper.find('[data-testid="vuln-about-more"]').exists()).toBe(false)
    })

    it('summarises components, versions and several CWEs', () => {
        const wrapper = mountSummary({
            components: [
                { name: 'a', versions: ['1'] }, { name: 'b', versions: [] },
                { name: 'c', versions: ['2', '3'] }, { name: 'd', versions: ['4'] },
            ],
            projectVersions: ['2.0', '1.0'],
            cwes: [{ id: 79, name: 'XSS' }, { id: 20 }],
        })
        const affects = wrapper.get('[data-testid="vuln-about-affects"]').text()
        expect(affects).toContain('a 1 · b · c 2, 3')
        expect(affects).toContain('+1 more')
        expect(affects).toContain('in 2 versions')
        const cwe = wrapper.get('[data-testid="vuln-about-cwe"]')
        expect(cwe.text()).toContain('CWE-79, CWE-20')
        expect(cwe.attributes('title')).toBe('CWE-79: XSS')
    })
})
