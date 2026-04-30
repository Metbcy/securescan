"use client";

import { useEffect, useState } from "react";

interface RiskScoreProps {
  score: number;
  size?: "lg" | "sm";
  label?: string;
}

function severityToken(score: number): {
  cssVar: string;
  textClass: string;
  bgClass: string;
} {
  if (score < 30)
    return {
      cssVar: "var(--accent)",
      textClass: "text-accent",
      bgClass: "bg-accent",
    };
  if (score < 60)
    return {
      cssVar: "var(--sev-medium)",
      textClass: "text-sev-medium",
      bgClass: "bg-sev-medium",
    };
  if (score < 80)
    return {
      cssVar: "var(--sev-high)",
      textClass: "text-sev-high",
      bgClass: "bg-sev-high",
    };
  return {
    cssVar: "var(--sev-critical)",
    textClass: "text-sev-critical",
    bgClass: "bg-sev-critical",
  };
}

export function RiskScore({
  score,
  size = "lg",
  label = "Risk score",
}: RiskScoreProps) {
  const tone = severityToken(score);
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  // For non-"lg" sizes we don't animate — use score directly. For
  // "lg" we ease from 0 → score on mount via requestAnimationFrame.
  // Storing 0 as the initial value here is safe because the
  // useEffect below replaces it before paint via rAF on the first
  // tick, and the non-"lg" code path never reads `animatedScore` —
  // it returns early before the SVG render.
  const [animatedScore, setAnimatedScore] = useState(0);
  const progress = (animatedScore / 100) * circumference;

  useEffect(() => {
    // Non-"lg" sizes aren't animated: the SVG ring isn't rendered for
    // them so `animatedScore` is unused, and a setState here would
    // trigger a cascading render with no visual effect (caught by
    // react-hooks/set-state-in-effect). Skip outright.
    if (size !== "lg") return;

    const duration = 600;
    const start = performance.now();
    let raf = 0;
    function animate(now: number) {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setAnimatedScore(Math.round(score * eased));
      if (t < 1) raf = requestAnimationFrame(animate);
    }
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [score, size]);

  if (size === "sm") {
    return (
      <span className="inline-flex items-center gap-1.5 tabular-nums">
        <span
          className={`w-4 h-4 rounded-full ${tone.bgClass}`}
          aria-hidden
        />
        <span className={`text-sm font-medium ${tone.textClass}`}>{score}</span>
      </span>
    );
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className="relative w-24 h-24"
        role="img"
        aria-label={`${label}: ${score} of 100`}
      >
        <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
          <circle
            cx="48"
            cy="48"
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth="6"
          />
          <circle
            cx="48"
            cy="48"
            r={radius}
            fill="none"
            stroke={tone.cssVar}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            className="transition-[stroke-dashoffset] duration-300 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span
            className={`text-2xl font-semibold tabular-nums ${tone.textClass}`}
          >
            {animatedScore}
          </span>
        </div>
      </div>
      <span className="text-xs font-medium uppercase tracking-wider text-muted">
        {label}
      </span>
    </div>
  );
}
