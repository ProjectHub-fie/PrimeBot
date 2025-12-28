import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  root: 'dashboard',
  build: {
    outDir: '../public',
    emptyOutDir: true
  },
  server: {
    port: 5000,
    host: '0.0.0.0',
    hmr: {
      port: 5000
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './dashboard/src'),
      '@assets': path.resolve(__dirname, './attached_assets')
    }
  }
})