import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "ProofChain AI",
  description: "Verify the origin and history of digital content.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav className="nav">
          <div className="nav-inner">
            <Link href="/" className="brand">
              Proof<span>Chain</span> AI
            </Link>
            <Link href="/">Verify</Link>
            <Link href="/register">Register</Link>
            <Link href="/dashboard">Dashboard</Link>
          </div>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
