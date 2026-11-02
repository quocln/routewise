import type { NextConfig } from "next";

// The webview loads static files from disk: no server exists at runtime, so
// nothing here may rely on SSR, server actions, API routes or image optimisation.
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
