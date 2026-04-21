/** @type {import('next').NextConfig} */
const nextConfig = {
	output: 'standalone',
	reactStrictMode: true,
	images: {
		remotePatterns: [],
	},
	allowedDevOrigins: [],
	poweredByHeader: false,
}

export default nextConfig
