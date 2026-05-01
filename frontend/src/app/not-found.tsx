// Per next-best-practices/error-handling.md: app/not-found.tsx is the
// custom 404 for any unmatched route. Server component by default — no
// 'use client' needed since there's no interactive state.

import Link from "next/link";
import { FileQuestion } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center px-4">
      <div className="w-full max-w-md text-center">
        <FileQuestion
          size={32}
          strokeWidth={1.5}
          className="text-muted mx-auto"
        />
        <h2 className="mt-3 text-base font-semibold text-foreground-strong">
          Page not found
        </h2>
        <p className="mt-1 text-sm text-muted">
          The URL you visited doesn&apos;t match any dashboard route.
        </p>
        <Link
          href="/"
          className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs hover:bg-surface-2"
        >
          ← Back to overview
        </Link>
      </div>
    </div>
  );
}
