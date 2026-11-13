import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import CodeAnalysisReport from '../CodeAnalysisReport.vue'
import CodeAnalysisRunOutcome from '../CodeAnalysisRunOutcome.vue'

const result = { assessment: { verdict: 'Not Affected', affected: false, confidence: 'High', exposure: 'none', summary: 'Summary', reasoning: 'Old reasoning', executive_summary: { vulnerability: 'Vulnerability', assessment: 'Assessment', why: ['Old rationale'] } } }

describe('full assessment report', () => {
    it('renders source links and evidence tables without active content', () => {
        const wrapper = mount(CodeAnalysisReport, { props: { markdown: '# Evidence\n\n| Ref | Version |\n|---|---|\n| master | 4.18.1 |\n\n[Source](https://example.com/advisory)\n\n<script>alert(1)</script><img src=x onerror=alert(1)><iframe src=x></iframe><a href="javascript:alert(1)" onclick="bad()">Unsafe</a>' } })
        expect(wrapper.find('table').exists()).toBe(true)
        expect(wrapper.text()).toContain('4.18.1')
        expect(wrapper.find('script,img,iframe').exists()).toBe(false)
        expect(wrapper.find('[onclick],[onerror]').exists()).toBe(false)
        expect(wrapper.find('a[href^="javascript:"]').exists()).toBe(false)
        expect(wrapper.get('a[href="https://example.com/advisory"]').attributes('rel')).toBe('noopener noreferrer')
    })
    it('prefers the report and falls back to rationale for old results', async () => {
        const wrapper = mount(CodeAnalysisRunOutcome, { props: { result: { ...result, assessment: { ...result.assessment, report_markdown: '## Repository evidence\nConcrete assessment' } } as any } })
        expect(wrapper.text()).toContain('Full assessment')
        expect(wrapper.text()).toContain('Concrete assessment')
        expect(wrapper.text()).not.toContain('Decision rationale')
        expect(wrapper.text()).not.toContain('Old rationale')
        await wrapper.setProps({ result: result as any })
        expect(wrapper.text()).toContain('Decision rationale')
        expect(wrapper.text()).toContain('Old rationale')
    })
})
