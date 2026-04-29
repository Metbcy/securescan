"use client";

import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  eyebrow?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ title, eyebrow, meta, actions }: PageHeaderProps) {
  return (
    <header className="flex items-end justify-between gap-6 pb-4 border-b border-border">
      <div className="min-w-0">
        {eyebrow && (
          <p className="text-xs font-medium text-muted uppercase tracking-wider mb-1">
            {eyebrow}
          </p>
        )}
        <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong">
          {title}
        </h1>
        {meta && <p className="text-sm text-muted mt-1">{meta}</p>}
      </div>
      {actions && (
        <div className="flex items-center gap-2 shrink-0">{actions}</div>
      )}
    </header>
  );
}

export interface StatLineItem {
  label: string;
  value: ReactNode;
  trail?: ReactNode;
}

export function StatLine({ items }: { items: StatLineItem[] }) {
  return (
    <dl className="flex items-stretch divide-x divide-border border-b border-border">
      {items.map((it) => (
        <div
          key={it.label}
          className="flex-1 px-5 py-4 first:pl-0 last:pr-0 min-w-0"
        >
          <dt className="text-xs font-medium text-muted uppercase tracking-wider mb-1">
            {it.label}
          </dt>
          <dd className="text-2xl font-semibold text-foreground-strong tabular-nums flex items-baseline gap-2">
            <span className="truncate">{it.value}</span>
            {it.trail && (
              <span className="text-sm font-normal text-muted">{it.trail}</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
