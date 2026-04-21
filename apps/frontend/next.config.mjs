/** @type {import('next').NextConfig} */
const nextConfig = {
	output: 'standalone',
	reactStrictMode: true,
	images: {
		domains: ['localhost', 'surface-lab.com', 'www.surface-lab.com'],
	},
	allowedDevOrigins: [],
	poweredByHeader: false,
}

export default nextConfig
