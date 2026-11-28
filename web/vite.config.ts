/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8080', ws: true },
      '/scim': 'http://localhost:8080',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The optional upstream LiveKit chunk is ~617 kB and loads only for SFU calls. The
    // application itself stays below 500 kB; use a 650 kB ceiling for that lazy dependency.
    chunkSizeWarningLimit: 650,
    rollupOptions: {
      output: {
        // Split stable UI dependencies out of the E3 application chunk.
        manualChunks: {
          react: ['react', 'react-dom/client'],
          'chat-controls': ['@base-ui/react'],
          qrcode: ['qrcode'],
        },
      },
    },
  },
  test: {
    // Each jsdom worker loads the real crypto cores; bound memory on shared hosts and CI.
    maxWorkers: 2,
    include: ['src/**/*.test.{ts,tsx}'],
    environment: 'jsdom',
    setupFiles: ['src/test-setup.ts'],
  },
});
