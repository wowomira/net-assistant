import { defineConfig } from 'vitest/config'

// Opt-in real local API / DOM integration. No network probes or business writes.
export default defineConfig({
  test: { environment: 'jsdom', include: ['tests-live/*.live.tsx'], testTimeout: 20_000 },
})
