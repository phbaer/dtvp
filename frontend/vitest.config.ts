import { fileURLToPath } from 'node:url'
import { mergeConfig, defineConfig, configDefaults } from 'vitest/config'
import viteConfig from './vite.config'

export default mergeConfig(
    viteConfig,
    defineConfig({
        test: {
            environment: 'jsdom',
            setupFiles: ['./src/setupTests.ts'],
            exclude: [...configDefaults.exclude, 'e2e/**'],
            root: fileURLToPath(new URL('./', import.meta.url)),
            coverage: {
                provider: 'v8',
                reporter: ['text', 'json', 'html'],
                include: ['src/**/*.{ts,vue}'],
                thresholds: {
                    statements: 79,
                    branches: 68,
                    functions: 76,
                    lines: 81
                },
                exclude: [
                    'node_modules/**',
                    'dist/**',
                    'src/**/__tests__/**',
                    'src/setupTests.ts',
                    '**/*.d.ts',
                    '**/*.test.ts',
                    '**/*.spec.ts',
                    'src/types/**',
                    'src/router.ts',
                    'src/main.ts'
                ]
            }
        }
    })
)
