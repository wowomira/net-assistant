import { defineConfig } from 'vitest/config'

const backend = { target: 'http://127.0.0.1:8001', changeOrigin: false }

export default defineConfig({
  base: '/console/',
  server: { proxy: { '/api': backend, '/health': backend, '/openapi.json': backend } },
  test: { environment: 'jsdom', restoreMocks: true },
})
