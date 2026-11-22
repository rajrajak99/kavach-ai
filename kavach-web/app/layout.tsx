import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kavach AI — Enterprise Pre-Merge Security Gate & 1-Click Self-Healing",
  description: "AST-based, sub-16ms pre-merge security gate for modern engineering teams with 0% false positives and 1-click compile-ready self-healing patches.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-obsidian-950 text-slateText-primary min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
