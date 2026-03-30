"use client";

import { useEffect, useState } from "react";

interface RiskScoreProps {
  score: number;
}

function getColor(score: number): string {
  if (score <= 30) return "#22c55e";
  if (score <= 60) return "#eab308";
  if (score <= 80) return "#f97316";
  return "#ef4444";
}

export function RiskScore({ score }: RiskScoreProps) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const progress = (animatedScore / 100) * circumference;
  const color = getColor(score);

  useEffect(() => {
    const duration = 800;
    const start = performance.now();
    const from = 0;

    function animate(now: number) {
      const elapsed = now - start;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setAnimatedScore(Math.round(from + (score - from) * eased));
      if (t < 1) requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
  }, [score]);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-44 h-44">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="none"
            stroke="#262626"
            strokeWidth="8"
          />
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold tabular-nums" style={{ color }}>
            {animatedScore}
          </span>
        </div>
      </div>
      <span className="text-sm text-[#a1a1aa] font-medium">Risk Score</span>
    </div>
  );
}
