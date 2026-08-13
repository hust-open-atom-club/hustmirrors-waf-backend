import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, '../internal/adminui/dist'),
    emptyOutDir: true,
    sourcemap: false,
  },
})
