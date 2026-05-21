import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://status.stacker.my"),
  title: {
    default: "Status Panel - Infrastructure and Container Operations",
    template: "%s | Status Panel",
  },
  description:
    "Status Panel is a lightweight infrastructure agent for health checks, metrics, Docker management, secure command execution, Vault-backed config, and Stacker deployments.",
  openGraph: {
    title: "Status Panel",
    description:
      "Operate containers, inspect metrics, execute signed commands, and deploy through Stacker.",
    url: "https://status.stacker.my",
    siteName: "Status Panel",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
