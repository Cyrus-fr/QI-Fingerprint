/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export: no backend, no server runtime. `next build` emits ./out.
  output: "export",
  // Emit /run/11/index.html rather than /run/11.html: the directory-index layout
  // every static host resolves without extra rewrite rules.
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
