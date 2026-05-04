// Vitest jsdom environment setup helpers.
// Stub window.scrollTo because jsdom does not implement it and tests may call it indirectly.
Object.defineProperty(window, 'scrollTo', {
    configurable: true,
    value: () => undefined,
})
