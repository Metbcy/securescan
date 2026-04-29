# SecureScan — Design System

This is the canonical design reference for the web UI (`frontend/`). Any component, page, or token-change PR must conform.

## Aesthetic commitment

**Refined neutral, dark-default, with one accent.** Not the AI-template "dark blue on black" — a warm-tinted graphite with a single committed accent. Severity colors derived from a single tonal ramp around the accent hue, *not* a rainbow of neon reds/yellows/blues.

Physical scene: AppSec engineer at 11pm on a 27" monitor, three browser windows open, scanning the SecureScan tab to spot a new critical. Reading. Not glancing.

Color strategy on the [Restrained / Committed / Full palette / Drenched] axis: **Restrained** (per the product register floor), with the Findings page allowed to commit to severity colors when a critical is present.

## Color tokens (OKLCH)

Defined in `frontend/src/app/globals.css` as CSS custom properties. Both themes ship; dark is default.

### Brand hue: 155 (moss / pine green)

Tints all neutrals at chroma 0.005–0.008 toward the brand hue.

### Dark theme (default)

```
--bg:           oklch(0.18 0.006 155)   /* near-black, paper-tinted */
--surface:      oklch(0.22 0.006 155)   /* card, panel */
--surface-2:    oklch(0.26 0.007 155)   /* elevated, hover */
--border:       oklch(0.32 0.008 155)
--border-strong:oklch(0.42 0.01 155)
--muted:        oklch(0.62 0.012 155)   /* secondary text */
--text:         oklch(0.92 0.008 155)   /* primary text */
--text-strong:  oklch(0.97 0.005 155)   /* headings */

--accent:       oklch(0.72 0.16 155)    /* moss green, primary actions, active state */
--accent-fg:    oklch(0.18 0.006 155)   /* on-accent text */
--accent-soft:  oklch(0.32 0.06 155)    /* accent-tinted surface for subtle highlight */

--ring:         oklch(0.72 0.16 155 / 0.6)  /* focus ring */
```

### Light theme

```
--bg:           oklch(0.985 0.003 155)
--surface:      oklch(1 0 0)
--surface-2:    oklch(0.97 0.004 155)
--border:       oklch(0.91 0.006 155)
--border-strong:oklch(0.85 0.008 155)
--muted:        oklch(0.48 0.012 155)
--text:         oklch(0.22 0.008 155)
--text-strong:  oklch(0.15 0.008 155)
--accent:       oklch(0.55 0.14 155)
--accent-fg:    oklch(0.985 0.003 155)
--accent-soft:  oklch(0.94 0.04 155)
```

### Severity ramp (single hue, lightness step)

NOT rainbow neon. All severity tokens sit on a coherent warm ramp from dark coral (critical) to warm amber (medium) and a desaturated cool for low/info. Same swatches in both themes; the page contrast carries them.

```
--sev-critical: oklch(0.58 0.18 25)    /* deep coral */
--sev-high:     oklch(0.66 0.16 45)    /* burnt orange */
--sev-medium:   oklch(0.74 0.14 75)    /* saffron */
--sev-low:      oklch(0.70 0.06 200)   /* dusty teal — NOT bright blue */
--sev-info:     oklch(0.65 0.02 240)   /* ash */

--sev-critical-bg: oklch(0.58 0.18 25 / 0.12)
--sev-high-bg:     oklch(0.66 0.16 45 / 0.12)
/* ...etc */
```

**Banned**: `#ff0000`, pure-blue `#3b82f6`-ish, neon yellow, stoplight semaphores. Severity is a tonal ramp, not a traffic light.

## Typography

One sans family. Tighter scale (1.125 ratio). System-stack fallback.

```
--font-sans: "Geist", ui-sans-serif, system-ui, -apple-system,
             BlinkMacSystemFont, "Segoe UI", sans-serif;
--font-mono: "Geist Mono", ui-monospace, "JetBrains Mono",
             "SF Mono", Menlo, Consolas, monospace;
```

Geist is loaded via `next/font/google` from `frontend/src/app/layout.tsx`. Inter is permitted as fallback but not the primary.

### Scale

| Token       | Size      | Use                                |
| ----------- | --------- | ---------------------------------- |
| `text-2xs`  | 0.6875rem | Caption, table footer, badges      |
| `text-xs`   | 0.75rem   | Labels, secondary metadata         |
| `text-sm`   | 0.8125rem | Body, table cells                  |
| `text-base` | 0.875rem  | Default body                       |
| `text-lg`   | 1rem      | Sub-section headings               |
| `text-xl`   | 1.125rem  | Card titles                        |
| `text-2xl`  | 1.375rem  | Page-section headings              |
| `text-3xl`  | 1.75rem   | Page titles                        |

Weights: 400 (body), 500 (label), 600 (emphasis, headings). No weight 700+ except for severity counts.

Line-height 1.5 for body, 1.3 for headings, 1.4 for table cells.

Body line-length capped at 70ch via `prose` utility. Tables uncapped.

## Spacing

4px base. Tailwind defaults. No custom values.

Rhythm:
- Card inner padding: `p-5` (20px)
- Section between cards: `gap-4` (16px) on grids, `space-y-6` (24px) for vertical sections
- Page gutters: `px-8` desktop, `px-4` mobile

## Layout system

**App shell**: persistent left side-nav (220px), sticky top bar (56px), main content. Side-nav collapses below 1024px to icon strip. Top bar has: project switcher / scan target context (left), command palette trigger (center), API status + theme toggle (right).

**Grids**: 12-column grid where applicable. Cards never span < 4 cols on desktop. Avoid identical-card grids — when two cards differ in importance, they differ in size.

**Page header pattern**: title + secondary metadata + primary action, on a single horizontal row. No big-number-card hero blocks. If metrics belong on a page, they integrate into the header strip, not stand-alone cards.

## Components

All built on shadcn/ui primitives where available; custom components live under `frontend/src/components/ui/`.

### Button
- Sizes: sm, md, lg. Radius: `rounded-md`.
- Variants: `default` (accent bg), `secondary` (surface-2 bg), `ghost` (transparent, hover surface-2), `destructive` (sev-critical bg).
- States: default, hover, focus-visible, active, disabled, loading. **All six** must be implemented.

### Badge
- Severity badges use `--sev-*-bg` background + `--sev-*` text. Dot prefix `●` for severity icon.
- Status badges: `completed`, `running`, `cancelled`, `failed` — derive from status hue, not arbitrary green/yellow/red.

### Table
- Density: `compact` (12px cell padding) by default. Toggle to `comfortable` (16px) per user preference.
- Sortable column headers: caret icon on hover/sort-active.
- Row states: default, hover (surface-2), selected (accent-soft), focus-within (ring).
- Pagination: footer with offset/limit, page-size selector.
- Empty state: message + suggested action, never "No data."

### Empty state
- Icon (24×24, 1.5 stroke width).
- Title: 1 line, `text-base font-medium`.
- Description: 1–2 lines, `text-sm text-muted`.
- Primary action: button if there is one obvious thing to do.
- Secondary link: docs/learn-more.

### Skeleton
- Used for any non-instant load. Match the shape of the eventual content (rows, not spinning circles).
- 1.5s shimmer animation, 250ms fade-in.

### Toast
- Sonner. Top-right. 4s default. Dismissible.

### Command palette (⌘K)
- Mounted at app root. Searches: pages, recent scans, scanners. Keyboard-driven.

## Motion

- Transitions: 150–200ms ease-out for hover/focus, 200–300ms ease-in-out for layout shift.
- No page-load orchestration.
- Spinners only inside buttons. Use skeletons for content.
- `prefers-reduced-motion` honored — replace any non-essential motion with cross-fade.

## Iconography

`lucide-react`. 1.5 stroke width. Sizes 14, 16, 20. No emoji in product surface.

## Severity rendering rules

Wherever a finding is shown:
1. Severity is **left-aligned** with a colored dot prefix.
2. Color reads via `--sev-*-bg` background AND `--sev-*` text — never just text.
3. Critical/High counts in page headers use `--sev-*` solid color, not muted.
4. Suppressed findings get a `strikethrough + muted` treatment with a tooltip explaining the suppression source.

## Dark/light handling

`next-themes`. Default to dark. Toggle in top bar. Persist to localStorage. Server-side render with `data-theme` attribute set from cookie to avoid flash.

## Banned (page-level)

- Hero-metric cards (big number + label trio) — replaced with header strip.
- Identical card grids — replaced with tables or differentiated layouts.
- Neon severity colors — single hue ramp only.
- Glassmorphism, gradient text, side-stripe accents > 1px, em-dashes used as separators.
- Inline `style=` attributes outside of token values.
- Any typography in `Inter` exclusively without Geist as primary.
- Any color outside the OKLCH token set.

## Validation

Every PR that touches `frontend/`:
1. `pnpm tsc --noEmit` passes.
2. `pnpm build` passes.
3. Visual review against this doc.
4. Both themes render without missing tokens.
5. No banned-list items introduced.
