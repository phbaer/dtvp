<script setup lang="ts">
import { onMounted, ref, useId } from 'vue'

const props = defineProps<{
    team: string
    withdraw: boolean
    busy: boolean
    error: string
    stale: boolean
}>()

const emit = defineEmits<{
    close: []
    request: [rationale: string]
}>()

const dialog = ref<HTMLDialogElement>()
const input = ref<HTMLTextAreaElement>()
const cancel = ref<HTMLButtonElement>()
const rationale = ref('')
const headingId = useId()
const rationaleId = useId()

onMounted(() => {
    dialog.value?.showModal()
    if (props.withdraw) cancel.value?.focus()
    else input.value?.focus()
})

const close = () => {
    if (props.busy) return
    dialog.value?.close()
    emit('close')
}
</script>

<template>
    <dialog
        ref="dialog"
        :aria-labelledby="headingId"
        class="m-auto w-[calc(100%_-_2rem)] max-w-md rounded-lg border border-gray-700 bg-gray-800 text-gray-200 shadow-2xl backdrop:bg-black/80"
        @cancel.prevent="close"
    >
        <form class="space-y-4 p-5" @submit.prevent="emit('request', rationale.trim())">
            <div>
                <h3 :id="headingId" class="text-lg font-bold">
                    {{ withdraw ? `Withdraw request for ${team}` : `Request changes from ${team}` }}
                </h3>
                <p class="mt-1 text-sm text-gray-300">
                    {{ withdraw
                        ? 'This closes the request and records the withdrawal in assessment history.'
                        : 'The saved verdict stays visible. Approval waits for this team to resubmit.' }}
                </p>
            </div>
            <div v-if="!withdraw">
                <label :for="rationaleId" class="block text-sm font-semibold">Rationale</label>
                <textarea
                    :id="rationaleId"
                    ref="input"
                    v-model="rationale"
                    maxlength="1000"
                    required
                    :readonly="busy"
                    rows="5"
                    class="mt-1 w-full rounded border border-gray-600 bg-gray-900 p-2 text-sm text-gray-100"
                ></textarea>
            </div>
            <p v-if="error" role="alert" class="text-sm text-red-300">{{ error }}</p>
            <div class="flex flex-wrap justify-end gap-2">
                <button
                    ref="cancel"
                    type="button"
                    :disabled="busy"
                    class="rounded bg-gray-700 px-4 py-2 text-sm font-bold hover:bg-gray-600 disabled:opacity-50"
                    @click="close"
                >Cancel</button>
                <button
                    type="submit"
                    :disabled="busy || stale || (!withdraw && !rationale.trim())"
                    class="rounded bg-amber-400 px-4 py-2 text-sm font-bold text-gray-950 hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-50"
                >{{ busy ? 'Saving…' : withdraw ? 'Withdraw request' : 'Request changes' }}</button>
            </div>
        </form>
    </dialog>
</template>
