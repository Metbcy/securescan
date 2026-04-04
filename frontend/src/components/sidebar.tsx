"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Shield,
  LayoutDashboard,
  ScanSearch,
  History,
  Settings,
  Menu,
  X,
  ArrowLeftRight,
  Package,
} from "lucide-react";

const navItems = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "New Scan", href: "/scan", icon: ScanSearch },
  { label: "Compare", href: "/compare", icon: ArrowLeftRight },
  { label: "History", href: "/history", icon: History },
  { label: "SBOM", href: "/sbom", icon: Package },
  { label: "Scanners", href: "/scanners", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile hamburger */}
      <button
        onClick={() => setOpen(true)}
        className="fixed top-4 left-4 z-50 md:hidden p-2 rounded-lg bg-[#141414] border border-[#262626] text-[#ededed]"
        aria-label="Open menu"
      >
        <Menu size={20} />
      </button>

      {/* Overlay */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed top-0 left-0 z-50 h-full w-60 bg-[#0e0e0e] border-r border-[#1a1a1a] flex flex-col transition-transform duration-200 md:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-5 border-b border-[#1a1a1a]">
          <Link href="/" className="flex items-center gap-2.5" onClick={() => setOpen(false)}>
            <Shield size={22} className="text-blue-500" />
            <span className="text-base font-semibold tracking-tight">SecureScan</span>
          </Link>
          <button
            onClick={() => setOpen(false)}
            className="md:hidden p-1 text-[#a1a1aa] hover:text-white"
            aria-label="Close menu"
          >
            <X size={18} />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setOpen(false)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? "bg-blue-500/10 text-blue-500"
                    : "text-[#a1a1aa] hover:text-white hover:bg-[#1a1a1a]"
                }`}
              >
                <item.icon size={18} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-[#1a1a1a]">
          <p className="text-xs text-[#52525b]">SecureScan v1.0</p>
        </div>
      </aside>
    </>
  );
}
