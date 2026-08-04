<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { login } from '../lib/api'

const route = useRoute()
const sessionExpired = computed(() => route.query.expired === '1')
</script>

<template>
    <div class="min-h-screen bg-gray-900 flex items-center justify-center font-sans">
        <div class="bg-gray-800 p-8 rounded-lg shadow-xl w-[400px] border border-gray-700">
            <div class="text-center mb-8">
                <div class="text-3xl font-bold bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent">DTVP</div>
                <div class="text-gray-400 mt-2 text-sm">Dependency Track Vulnerability Processor</div>
            </div>
            
            <div class="space-y-6">
                <p
                    v-if="sessionExpired"
                    class="rounded border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-100"
                    role="status"
                >
                    Your DTVP session ended. Sign in again to return to your previous screen.
                </p>
                <button 
                    @click="login()"
                    class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded transition-all duration-200 shadow-lg shadow-blue-900/20 active:scale-[0.98] cursor-pointer"
                >
                    Sign in with SSO
                </button>

                <div class="mt-8 pt-8 border-t border-gray-700 text-center">
                    <p class="text-xs text-gray-500 italic">Connected to Dependency-Track Instance</p>
                </div>
            </div>
        </div>
    </div>
</template>
