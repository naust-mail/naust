import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig(({ command }) => ({
  plugins: [vue()],
  // In dev, serve from root so router and API proxy work without /admin prefix complexity.
  // In build, assets land at /admin/assets/, served statically by nginx.
  base: command === 'serve' ? '/' : '/admin/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // The dist tree mirrors the URL space: nginx points its root at
    // the installed dist/ and /admin/* maps straight onto dist/admin/*.
    outDir: 'dist/admin',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      // managerd (Go daemon) serves the /api prefix natively.
      '/api': {
        target: 'http://127.0.0.1:10223',
        changeOrigin: true,
      },
    },
  },
}))
