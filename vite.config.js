import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  server: {
    // Your updated host
    host: '127.0.0.1',
    port: 5173,

    // Your updated ngrok domain
    allowedHosts: [
      '.ngrok-free.dev'
    ],

    // This helps with HMR (Hot Module Replacement) when behind a proxy
    hmr: {
      overlay: false
    },

    // --- MOVED PROXY INSIDE server: { ... } ---
    proxy: {
      // This says "forward all /api requests"
      '/api': {
        // This is your backend server
        target: 'http://localhost:3001',
        // This is necessary for virtual hosts
        changeOrigin: true,
        // We don't need rewrite because your backend paths already start with /api
      }
    }
    // --- END OF PROXY OBJECT ---
  }
})

