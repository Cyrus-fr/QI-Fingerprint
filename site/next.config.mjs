/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export: no backend, no server runtime. `next build` emits ./out.
  output: "export",
  // Emit /run/11/index.html rather than /run/11.html: the directory-index layout
  // every static host resolves without extra rewrite rules.
  trailingSlash: true,
  // A GitHub project page serves from /<repo>, not from the domain root, and the
  // export hard-codes its asset URLs at build time. Driven by the environment so
  // the local build and `next dev` stay at the root and only the Pages build is
  // prefixed. Next derives assetPrefix from this, so every /_next/ URL moves too.
  basePath: process.env.PAGES_BASE_PATH || "",
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
