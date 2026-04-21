import type { Metadata } from "next"
import { Geist_Mono, Inter, Raleway } from "next/font/google"

import "./globals.css"
import { AppProviders } from "@/components/app-providers"
import { cn } from "@/utils/utils"

const ralewayHeading = Raleway({ subsets: ["latin"], variable: "--font-heading" })
const inter = Inter({ subsets: ["latin"], variable: "--font-sans" })
const fontMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
})

export const metadata: Metadata = {
  title: "SurfaceLab",
  description: "SurfaceLab security reporting dashboard",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn(
        "dark antialiased",
        fontMono.variable,
        "font-sans",
        inter.variable,
        ralewayHeading.variable
      )}
    >
      <body>
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  )
}
