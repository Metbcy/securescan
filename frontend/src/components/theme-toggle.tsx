"use client";

import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = mounted ? resolvedTheme === "dark" : true;

  function toggle() {
    setTheme(isDark ? "light" : "dark");
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-surface text-muted transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:text-foreground"
    >
      {mounted ? (
        isDark ? (
          <Sun size={16} strokeWidth={1.5} aria-hidden />
        ) : (
          <Moon size={16} strokeWidth={1.5} aria-hidden />
        )
      ) : (
        <Sun size={16} strokeWidth={1.5} aria-hidden />
      )}
    </button>
  );
}
