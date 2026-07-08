const reinstallHint = [
  'Rolldown native binding is missing from frontend/node_modules.',
  '',
  'Fix the frontend install with:',
  '  cd frontend && npm ci --include=optional',
  '',
  'If node_modules is cached or bind-mounted from another OS/container image,',
  'remove that node_modules directory first and run the command again.',
  'Do not install with --omit=optional, --no-optional, or npm_config_optional=false.',
].join('\n')

try {
  await import('rolldown')
} catch (error) {
  console.error(reinstallHint)
  console.error('')
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
