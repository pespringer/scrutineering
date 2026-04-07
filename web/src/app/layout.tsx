import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Container Sentinel — Security Dashboard",
  description: "Container vulnerability scanning and remediation dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-950 text-gray-100 antialiased">
        <div className="flex min-h-screen">
          {/* Sidebar */}
          <aside className="w-56 bg-gray-900 border-r border-gray-800 flex-shrink-0 hidden md:block">
            <div className="p-4">
              <h1 className="text-sm font-bold text-indigo-400 tracking-wide">CONTAINER SENTINEL</h1>
            </div>
            <nav className="px-3 space-y-1">
              {[
                { href: "/", label: "Overview", icon: "📊" },
                { href: "/images", label: "Images", icon: "🖼️" },
                { href: "/scans", label: "Scans", icon: "🔍" },
              ].map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  className="flex items-center gap-2 px-3 py-2 text-sm rounded-md text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
                >
                  <span>{link.icon}</span>
                  {link.label}
                </a>
              ))}
            </nav>
          </aside>

          {/* Mobile-friendly content */}
          <main className="flex-1 min-w-0 p-4 md:p-6">
            <div className="mb-4 flex items-center gap-2 md:hidden">
              <span className="text-xs font-bold text-indigo-400 tracking-wide">CONTAINER SENTINEL</span>
            </div>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
