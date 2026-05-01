import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  allowedDevOrigins: ["127.0.0.1", "localhost"],

  // /compare and /diff used to be two pages calling the same backend
  // endpoint with the same 2-dropdown UI — pure noise. Consolidated
  // into /diff (matches the `securescan diff` CLI command name) in
  // v0.11.8. The 308 keeps any bookmarks / external links / saved
  // browser history working.
  async redirects() {
    return [
      {
        source: "/compare",
        destination: "/diff",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
