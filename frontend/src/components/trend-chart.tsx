"use client";

import { useState } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";
import type { TrendPoint } from "@/lib/api";

interface TrendChartProps {
  data: TrendPoint[];
}

type ChartMode = "risk" | "findings";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export function TrendChart({ data }: TrendChartProps) {
  const [mode, setMode] = useState<ChartMode>("risk");

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-[#71717a] text-sm">
        No trend data available yet. Complete more scans to see trends.
      </div>
    );
  }

  return (
    <div>
      {/* Toggle */}
      <div className="flex gap-1 mb-4 bg-[#1a1a1a] rounded-lg p-1 w-fit">
        <button
          onClick={() => setMode("risk")}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            mode === "risk"
              ? "bg-blue-600 text-white"
              : "text-[#a1a1aa] hover:text-white"
          }`}
        >
          Risk Score
        </button>
        <button
          onClick={() => setMode("findings")}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            mode === "findings"
              ? "bg-blue-600 text-white"
              : "text-[#a1a1aa] hover:text-white"
          }`}
        >
          Findings
        </button>
      </div>

      {/* Chart */}
      <div className="w-full h-72">
        <ResponsiveContainer width="100%" height="100%">
          {mode === "risk" ? (
            <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis
                dataKey="date"
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                axisLine={{ stroke: "#262626" }}
                tickLine={false}
                tickFormatter={(v: string) => {
                  const d = new Date(v);
                  return `${d.getMonth() + 1}/${d.getDate()}`;
                }}
              />
              <YAxis
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                domain={[0, 100]}
              />
              <Tooltip
                contentStyle={{
                  background: "#1a1a1a",
                  border: "1px solid #262626",
                  borderRadius: "8px",
                  color: "#ededed",
                  fontSize: 13,
                }}
              />
              <Line
                type="monotone"
                dataKey="risk_score"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={{ fill: "#3b82f6", r: 3 }}
                name="Risk Score"
              />
            </LineChart>
          ) : (
            <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis
                dataKey="date"
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                axisLine={{ stroke: "#262626" }}
                tickLine={false}
                tickFormatter={(v: string) => {
                  const d = new Date(v);
                  return `${d.getMonth() + 1}/${d.getDate()}`;
                }}
              />
              <YAxis
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#1a1a1a",
                  border: "1px solid #262626",
                  borderRadius: "8px",
                  color: "#ededed",
                  fontSize: 13,
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: 12, color: "#a1a1aa" }}
              />
              <Area
                type="monotone"
                dataKey="critical"
                stackId="1"
                stroke={SEVERITY_COLORS.critical}
                fill={SEVERITY_COLORS.critical}
                fillOpacity={0.6}
                name="Critical"
              />
              <Area
                type="monotone"
                dataKey="high"
                stackId="1"
                stroke={SEVERITY_COLORS.high}
                fill={SEVERITY_COLORS.high}
                fillOpacity={0.6}
                name="High"
              />
              <Area
                type="monotone"
                dataKey="medium"
                stackId="1"
                stroke={SEVERITY_COLORS.medium}
                fill={SEVERITY_COLORS.medium}
                fillOpacity={0.6}
                name="Medium"
              />
              <Area
                type="monotone"
                dataKey="low"
                stackId="1"
                stroke={SEVERITY_COLORS.low}
                fill={SEVERITY_COLORS.low}
                fillOpacity={0.6}
                name="Low"
              />
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
}
