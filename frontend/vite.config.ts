import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const contract = readFileSync(new URL('../dtvp/api_contract.py', import.meta.url), 'utf8')
const version = contract.match(/^API_VERSION = "(v[1-9][0-9]*)"$/m)?.[1]
if (!version) throw new Error('Missing canonical API_VERSION in dtvp/api_contract.py')
export const apiPrefix = `/api/${version}`
export default defineConfig({
  define: { __DTVP_API_PREFIX__: JSON.stringify(apiPrefix) },
  plugins: [vue()],
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8000', '/auth': 'http://127.0.0.1:8000' } },
})
