<script setup lang="ts">
import type { KnowledgeCodeAnalysis } from '../knowledgeApi'

defineProps<{ items: KnowledgeCodeAnalysis[] }>()
const label = (value: string) => value.replaceAll('_', ' ')
const providerClaims = (item: KnowledgeCodeAnalysis) => ['llm_provider', 'llm_backend', 'model'].map(key => item.provider_claim?.[key]).filter((value): value is string => typeof value === 'string' && Boolean(value)).map(value => value.length > 200 ? value.slice(0, 200) + '…' : value).join(' · ')
</script>

<template>
  <details v-if="items.length" class="analysis-evidence">
    <summary>Code analysis evidence ({{ items.length }})</summary>
    <p class="hint">External proposals require human assessment and independent review. They do not establish DTVP approval.</p>
    <details v-for="item in items" :key="item.id" class="analysis-result">
      <summary>{{ item.source_label }} · {{ item.verdict || 'Unknown verdict' }} · {{ item.current ? 'Current inputs' : 'Historical inputs' }}</summary>
      <p class="analysis-summary">{{ item.summary || 'No provider summary supplied.' }}</p>
      <p><small>{{ item.provider }} · Confidence claimed: {{ item.confidence || 'Unknown' }}</small></p>
      <p v-if="item.application_eligible && item.proposal_state">Applicability proposal: {{ label(item.proposal_state) }}. Available for human assessment.</p>
      <p v-else class="hint">Not eligible as a current applicability proposal.</p>
      <ul v-if="item.ineligibility_reasons.length" aria-label="Analysis limitations"><li v-for="reason in item.ineligibility_reasons" :key="reason">{{ label(reason) }}</li></ul>
      <details v-if="item.rationale"><summary>Analysis reasoning</summary><p class="analysis-summary">{{ item.rationale }}</p></details>
      <details>
        <summary>Source consistency and provenance</summary>
        <p class="hint">Receipt and report consistency checks do not authenticate the provider or verify the built binary. Repository authorization and the job/report association are not verified by this evidence import.</p>
        <dl>
          <dt>Package/version claim</dt><dd>{{ item.source_proof.target_claim_consistent ? 'Consistent with pinned inputs' : 'Consistency not established' }}</dd>
          <dt>Source commit claim</dt><dd>{{ item.source_proof.source_commit_consistent ? 'Consistent with pinned inputs' : 'Consistency not established' }}</dd>
          <dt>Expected commit</dt><dd><code>{{ item.source_proof.source_binding.expected_commit || 'Unknown' }}</code></dd>
          <dt>Requested commit</dt><dd><code>{{ item.source_proof.source_binding.requested_commit || 'Unknown' }}</code></dd>
          <dt>Resolved commit</dt><dd><code>{{ item.source_proof.source_binding.resolved_commit || 'Unknown' }}</code></dd>
          <dt>Input state</dt><dd><code>{{ item.source_receipt?.state || 'Unknown' }}</code></dd>
          <dt>Report SHA-256</dt><dd><code>{{ item.report_sha256 }}</code></dd>
          <dt>Receipt SHA-256</dt><dd><code>{{ item.receipt_sha256 }}</code></dd>
        </dl>
        <p v-if="item.source_proof.source_binding.reason">{{ item.source_proof.source_binding.reason }}</p>
        <p v-if="providerClaims(item)"><small>Provider/model claims: {{ providerClaims(item) }}</small></p>
      </details>
      <details v-if="item.scoring_blockers.length"><summary>Scoring proposal limitations</summary><ul><li v-for="reason in item.scoring_blockers" :key="reason">{{ label(reason) }}</li></ul></details>
    </details>
  </details>
</template>

<style scoped>
.analysis-evidence { padding: 1rem; border-block: 1px solid var(--border, #64748b33); }
.analysis-evidence summary { cursor: pointer; overflow-wrap: anywhere; }
.analysis-result { margin-top: .65rem; padding-top: .45rem; border-top: 1px solid var(--border, #64748b33); }
.analysis-result > summary { font-weight: 500; }
.analysis-result details { margin-block: .55rem; }
.analysis-summary { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 24rem; overflow: auto; }
dl { display: grid; grid-template-columns: minmax(6rem, 1fr) minmax(0, 2fr); gap: .4rem .75rem; }
dt { opacity: .75; }
dd { margin: 0; overflow-wrap: anywhere; }
code { font-size: .8rem; }
@media (max-width: 650px) { dl { grid-template-columns: minmax(0, 1fr); } dd { margin-bottom: .45rem; } }
</style>
