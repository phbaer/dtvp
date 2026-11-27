import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnAboutSummary from '../VulnAboutSummary.vue'

const mountSummary = (props: Record<string, unknown> = {}) => mount(VulnAboutSummary, {
    props: { links: [], ...props },
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

    it('keeps the advisory title in the main header, with an empty-description placeholder', () => {
        const wrapper = mountSummary({ description: '' })
        expect(wrapper.find('[data-testid="vuln-about-title"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="vuln-about-description"]').text()).toBe('No description available.')
        expect(wrapper.find('[data-testid="vuln-about-more"]').exists()).toBe(false)
    })

    it('keeps compact CWE identifiers with full names on hover and for assistive technology', () => {
        const wrapper = mountSummary({
            cwes: [{ id: 79, name: 'XSS' }, { id: 20 }],
        })
        expect(wrapper.find('[data-testid="vuln-about-affects"]').exists()).toBe(false)
        const cwe = wrapper.get('[data-testid="vuln-about-cwe"]')
        expect(cwe.get('dd').text()).toBe('CWE-79, CWE-20')
        expect(cwe.attributes('title')).toContain('CWE-79: XSS')
        expect(cwe.get('dd').attributes('aria-label')).toBe('CWE-79: XSS\nCWE-20')
        expect(cwe.find('svg').exists()).toBe(true)
    })

    it('gives advisory icons descriptive hover and accessible labels without repeating link icons', () => {
        const wrapper = mountSummary({
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
            recommendation: 'Upgrade.', links: [{ label: 'NVD', url: 'https://nvd.nist.gov/' }, { label: 'MITRE', url: 'https://www.cve.org/' }],
        })
        const facts = wrapper.findAll('dt')
        expect(facts.map(term => term.attributes('title'))).toEqual([
            'CVSS attack conditions from the advisory base vector', 'Advisory remediation recommendation', 'External advisory references',
        ])
        expect(facts.every(term => term.find('svg[aria-hidden="true"]').exists() && term.find('.sr-only').text())).toBe(true)
        expect(wrapper.get('[data-testid="vuln-about-references"]').findAll('svg')).toHaveLength(1)
        expect(wrapper.findAll('a').map(link => link.text())).toEqual(['NVD', 'MITRE'])
    })
})
