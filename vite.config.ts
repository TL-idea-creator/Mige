import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// Tauri 开发时前端跑在 5173，构建产物给 src-tauri 打包
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] }
  },
  build: {
    target: 'chrome105',
    minify: 'esbuild',
    sourcemap: false
  }
});
