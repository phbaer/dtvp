<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Copy, KeyRound, RefreshCw, Trash2 } from '@lucide/vue'
import {
    createAccessToken,
    getMcpEndpointUrl,
    listAccessTokenAudit,
    listAccessTokens,
    revokeAccessToken,
} from '../lib/api'
import type { AccessTokenAuditEntry, AccessTokenInfo, AccessTokenListing } from '../lib/api'

const props = defineProps<{ isReviewer: boolean }>()

const listing = ref<AccessTokenListing | null>(null)
const audit = ref<AccessTokenAuditEntry[]>([])
const loading = ref(false)
const error = ref('')

const name = ref('')
const allowWrite = ref(false)
const expiresInDays = ref(90)
const creating = ref(false)
const createdToken = ref('')
const createdName = ref('')
const copied = ref(false)
const revoking = ref('')

const mcpUrl = getMcpEndpointUrl()

const errorMessage = (err: any, fallback: string): string =>
    err?.response?.data?.detail || err?.message || fallback

const formatDate = (value: string | null): string =>
    value ? new Date(value).toLocaleString() : 'Never'

const tokenStatus = (token: AccessTokenInfo): 'Active' | 'Revoked' | 'Expired' => {
    if (token.revoked_at) return 'Revoked'
    if (new Date(token.expires_at).getTime() <= Date.now()) return 'Expired'
    return 'Active'
}

const canCreate = computed(() =>
    name.value.trim().length > 0
    && Number.isInteger(expiresInDays.value)
    && expiresInDays.value >= 1
    && expiresInDays.value <= (listing.value?.max_expiry_days ?? 365),
)

const load = async () => {
    loading.value = true
    error.value = ''
    try {
        listing.value = await listAccessTokens()
        audit.value = listing.value.enabled ? await listAccessTokenAudit() : []
    } catch (err: any) {
        error.value = errorMessage(err, 'Failed to load access tokens')
    } finally {
        loading.value = false
    }
}

const create = async () => {
    if (!canCreate.value || creating.value) return
    creating.value = true
    error.value = ''
    createdToken.value = ''
    copied.value = false
    try {
        const created = await createAccessToken({
            name: name.value.trim(),
            scopes: allowWrite.value ? ['read', 'write'] : ['read'],
            expires_in_days: expiresInDays.value,
        })
        createdToken.value = created.token
        createdName.value = created.name
        name.value = ''
        allowWrite.value = false
        await load()
    } catch (err: any) {
        error.value = errorMessage(err, 'Failed to create the token')
    } finally {
        creating.value = false
    }
}

const copyToken = async () => {
    try {
        await navigator.clipboard.writeText(createdToken.value)
        copied.value = true
    } catch {
        error.value = 'Copying failed. Select the token and copy it manually.'
    }
}

const revoke = async (token: AccessTokenInfo) => {
    if (!window.confirm(`Revoke "${token.name}"? Clients using it lose access immediately.`)) return
    revoking.value = token.id
    error.value = ''
    try {
        await revokeAccessToken(token.id)
        await load()
    } catch (err: any) {
        error.value = errorMessage(err, 'Failed to revoke the token')
    } finally {
        revoking.value = ''
    }
}

const auditTarget = (entry: AccessTokenAuditEntry): string => {
    const target = entry.target || {}
    return [target.project, target.vulnerability, target.team]
        .filter((part) => typeof part === 'string' && part)
        .join(' · ')
}

onMounted(load)
</script>

<template>
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg" data-testid="access-tokens-panel">
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h3 class="text-xl font-bold text-gray-200 flex items-center gap-2">
                    <KeyRound :size="18" aria-hidden="true" />
                    Access Tokens
                </h3>
                <p class="mt-1 text-sm text-gray-400">
                    Let an AI agent or script read vulnerabilities and draft team assessments as you.
                    Drafts stay pending until a reviewer approves them.
                </p>
            </div>
            <button
                type="button"
                class="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-50"
                :disabled="loading"
                @click="load"
            >
                <RefreshCw :size="14" :class="{ 'animate-spin': loading }" aria-hidden="true" />
                Refresh
            </button>
        </div>

        <div v-if="error" role="alert" class="mb-4 p-3 bg-red-900/30 border border-red-800 text-red-400 rounded text-sm">
            {{ error }}
        </div>

        <p v-if="loading && !listing" class="text-sm text-gray-400">Loading access tokens…</p>

        <div
            v-else-if="listing && !listing.enabled"
            class="p-4 rounded border border-gray-700 bg-gray-900/40 text-sm text-gray-300"
            data-testid="access-tokens-disabled"
        >
            Access tokens are turned off on this server. An administrator can enable them with
            <code class="text-blue-300">DTVP_ACCESS_TOKENS_ENABLED=true</code>.
        </div>

        <template v-else-if="listing">
            <section class="mb-6 rounded border border-gray-700 bg-gray-900/40 p-4">
                <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">MCP endpoint</h4>
                <code class="block break-all text-sm text-blue-300" data-testid="mcp-url">{{ mcpUrl }}</code>
                <p class="mt-2 text-xs text-gray-400">
                    Configure your MCP client with this URL and the header
                    <code>Authorization: Bearer &lt;token&gt;</code>.
                </p>
            </section>

            <section
                v-if="createdToken"
                class="mb-6 rounded border border-green-800 bg-green-900/20 p-4"
                data-testid="created-token"
            >
                <h4 class="text-sm font-semibold text-green-300">Token "{{ createdName }}" created</h4>
                <p class="mt-1 text-xs text-gray-300">
                    Copy it now. It is not stored in readable form and cannot be shown again.
                </p>
                <div class="mt-3 flex items-center gap-2">
                    <code class="flex-1 break-all rounded bg-gray-900 p-2 text-xs text-green-200">{{ createdToken }}</code>
                    <button
                        type="button"
                        class="inline-flex items-center gap-1 rounded bg-green-700 px-3 py-2 text-xs font-semibold text-white hover:bg-green-600"
                        @click="copyToken"
                    >
                        <Copy :size="14" aria-hidden="true" />
                        {{ copied ? 'Copied' : 'Copy' }}
                    </button>
                </div>
            </section>

            <form class="mb-6 rounded border border-gray-700 bg-gray-900/40 p-4" @submit.prevent="create">
                <h4 class="text-xs font-bold uppercase text-gray-500 mb-3">New token</h4>
                <div class="grid gap-4 md:grid-cols-[2fr_1fr]">
                    <label class="block text-sm text-gray-300">
                        Name
                        <input
                            v-model="name"
                            type="text"
                            maxlength="100"
                            placeholder="e.g. triage agent on my laptop"
                            class="mt-1 w-full rounded border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            data-testid="token-name"
                        />
                        <span class="mt-1 block text-xs text-gray-500">
                            Shown next to your name on every assessment written with this token.
                        </span>
                    </label>
                    <label class="block text-sm text-gray-300">
                        Expires after (days)
                        <input
                            v-model.number="expiresInDays"
                            type="number"
                            min="1"
                            :max="listing.max_expiry_days"
                            class="mt-1 w-full rounded border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            data-testid="token-expiry"
                        />
                        <span class="mt-1 block text-xs text-gray-500">1 to {{ listing.max_expiry_days }}</span>
                    </label>
                </div>
                <label class="mt-4 flex items-start gap-2 text-sm text-gray-300">
                    <input v-model="allowWrite" type="checkbox" class="mt-1" data-testid="token-write" />
                    <span>
                        Allow drafting team assessments
                        <span class="block text-xs text-gray-500">
                            Without this the token can only read. It can never approve, change CVSS or SSVC,
                            or edit settings.
                        </span>
                    </span>
                </label>
                <button
                    type="submit"
                    :disabled="!canCreate || creating"
                    class="mt-4 rounded bg-blue-600 px-4 py-2 text-sm font-bold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                    data-testid="token-create"
                >
                    {{ creating ? 'Creating…' : 'Create token' }}
                </button>
            </form>

            <section class="mb-6">
                <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">Your tokens</h4>
                <p v-if="listing.tokens.length === 0" class="text-sm text-gray-400" data-testid="tokens-empty">
                    You have no tokens yet.
                </p>
                <div v-else class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-gray-300">
                        <thead class="text-xs uppercase text-gray-500">
                            <tr>
                                <th class="py-2 pr-4">Name</th>
                                <th class="py-2 pr-4">Access</th>
                                <th class="py-2 pr-4">Status</th>
                                <th class="py-2 pr-4">Last used</th>
                                <th class="py-2 pr-4">Expires</th>
                                <th class="py-2"><span class="sr-only">Actions</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr
                                v-for="token in listing.tokens"
                                :key="token.id"
                                class="border-t border-gray-700"
                                data-testid="token-row"
                            >
                                <td class="py-2 pr-4 font-medium text-gray-100">{{ token.name }}</td>
                                <td class="py-2 pr-4">
                                    {{ token.scopes.includes('write') ? 'Read and draft' : 'Read only' }}
                                </td>
                                <td class="py-2 pr-4">
                                    <span
                                        :class="tokenStatus(token) === 'Active' ? 'text-green-400' : 'text-gray-500'"
                                    >{{ tokenStatus(token) }}</span>
                                </td>
                                <td class="py-2 pr-4">{{ formatDate(token.last_used_at) }}</td>
                                <td class="py-2 pr-4">{{ formatDate(token.expires_at) }}</td>
                                <td class="py-2 text-right">
                                    <button
                                        v-if="tokenStatus(token) === 'Active'"
                                        type="button"
                                        class="inline-flex items-center gap-1 rounded border border-red-800 px-2 py-1 text-xs text-red-300 hover:bg-red-900/40 disabled:opacity-50"
                                        :disabled="revoking === token.id"
                                        :aria-label="`Revoke ${token.name}`"
                                        data-testid="token-revoke"
                                        @click="revoke(token)"
                                    >
                                        <Trash2 :size="12" aria-hidden="true" />
                                        {{ revoking === token.id ? 'Revoking…' : 'Revoke' }}
                                    </button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section>
                <h4 class="text-xs font-bold uppercase text-gray-500 mb-2">
                    {{ props.isReviewer ? 'Recent changes made with tokens (all users)' : 'Recent changes made with your tokens' }}
                </h4>
                <p v-if="audit.length === 0" class="text-sm text-gray-400" data-testid="audit-empty">
                    No changes have been made with a token yet.
                </p>
                <div v-else class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-gray-300">
                        <thead class="text-xs uppercase text-gray-500">
                            <tr>
                                <th class="py-2 pr-4">When</th>
                                <th class="py-2 pr-4">User</th>
                                <th class="py-2 pr-4">Token</th>
                                <th class="py-2 pr-4">Change</th>
                                <th class="py-2">Result</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr
                                v-for="entry in audit"
                                :key="entry.id"
                                class="border-t border-gray-700"
                                data-testid="audit-row"
                            >
                                <td class="py-2 pr-4 whitespace-nowrap">{{ formatDate(entry.occurred_at) }}</td>
                                <td class="py-2 pr-4">{{ entry.username }}</td>
                                <td class="py-2 pr-4">{{ entry.agent }}</td>
                                <td class="py-2 pr-4">{{ auditTarget(entry) || entry.action }}</td>
                                <td class="py-2" :title="entry.detail">
                                    <span :class="entry.outcome === 'success' ? 'text-green-400' : 'text-amber-400'">
                                        {{ entry.outcome }}
                                    </span>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>
        </template>
    </div>
</template>
