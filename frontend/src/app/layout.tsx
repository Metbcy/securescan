import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { Sidebar } from "@/components/sidebar";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SecureScan — Security Dashboard",
  description: "Security scanning dashboard for code, dependencies, and infrastructure",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} dark h-full antialiased`}>
      <body className="min-h-full flex bg-[#0a0a0a] text-[#ededed]">
        <Sidebar />
        <main className="flex-1 min-h-screen md:ml-60 p-6 md:p-8">
          {children}
        </main>
      </body>
    </html>
  );
}
