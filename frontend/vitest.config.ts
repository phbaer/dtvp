import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { apiPrefix } from './vite.config.ts'

export default defineConfig({ define: { __DTVP_API_PREFIX__: JSON.stringify(apiPrefix) }, plugins: [vue()], test: { environment: 'jsdom', include: ['src/**/*.spec.ts'] } })
