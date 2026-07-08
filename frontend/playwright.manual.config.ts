/// <reference types="node" />
import { defineConfig } from '@playwright/test'
import baseConfig from './playwright.config'

export default defineConfig({
    ...baseConfig,
    fullyParallel: false,
    testMatch: '**/*.manual.ts',
    timeout: 60_000,
    workers: 1,
})
