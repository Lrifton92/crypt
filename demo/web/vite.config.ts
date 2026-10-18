import { defineConfig } from "vite";

// Served from https://lrifton92.github.io/crypt/ ; CRYPT_BASE=/ for a local preview at the root.
export default defineConfig({
  base: process.env.CRYPT_BASE ?? "/crypt/",
  build: { target: "es2020", assetsInlineLimit: 0 },
  server: { fs: { allow: [".."] } },
});
