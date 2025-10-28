import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ["crypto", "stream"],
      globals: {
        Buffer: true,
      },
    }),
    tailwindcss(),
  ],
  define: {
    "process.env.NODE_DEBUG": false,
    "process.browser": true,
  },
});
