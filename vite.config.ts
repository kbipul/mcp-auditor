import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Required for GitHub Pages: site serves from /mcp-auditor/
  base: "/mcp-auditor/",
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1500 },
});
