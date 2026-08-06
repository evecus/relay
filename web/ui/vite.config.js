import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // 相对路径，确保被 axum 静态服务挂载在 / 下时资源正常加载
  base: './',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    // 生成 sourcemap 便于调试，体积可接受
    sourcemap: false,
    // 生产构建清理 dist
    emptyOutDir: true,
    // 单文件 chunk 策略，减少请求数
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
  },
  server: {
    // 开发时代理 API 到本地 relay web 服务
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/metrics': 'http://127.0.0.1:8080',
    },
  },
})
