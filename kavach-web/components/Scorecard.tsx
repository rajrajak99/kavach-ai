"use client";

import React from "react";
import { Download, FileText, CheckCircle2, AlertOctagon, ShieldAlert } from "lucide-react";

interface ScorecardProps {
  score?: number;
  grade?: string;
  gradeLabel?: string;
  color?: string;
  cvssMax?: number;
  criticalCount?: number;
  warningCount?: number;
  onDownloadReport: (type: "soc2" | "json" | "summary") => void;
}

export default function Scorecard({
  score = 100,
  grade = "A",
  gradeLabel = "Deterministic AST Verified",
  color = "#22C58B",
  cvssMax = 0,
  criticalCount = 0,
  warningCount = 0,
  onDownloadReport,
}: ScorecardProps) {
  const isPassed = criticalCount === 0;
  const safeCvss = Number(cvssMax) || 0;

  return (
    <div className="bg-obsidian-850 border border-obsidian-700 rounded-lg p-4 mb-4 shadow-md">
      {/* Top Score Row */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center font-bold text-lg font-mono"
            style={{
              backgroundColor: `${color}15`,
              color: color,
              border: `1px solid ${color}40`,
            }}
          >
            {grade}
          </div>
          <div>
            <div className="text-sm font-semibold text-slateText-primary flex items-center gap-2">
              <span>Security Health: {score}/100</span>
              <span className="text-[11px] px-2 py-0.5 rounded font-mono font-medium" style={{ backgroundColor: `${color}15`, color: color }}>
                {isPassed ? "PASS" : "BLOCKED"}
              </span>
            </div>
            <p className="text-[11.5px] text-slateText-secondary">{gradeLabel}</p>
          </div>
        </div>

        <div className="text-right">
          <span className="text-[10px] text-slateText-muted uppercase tracking-wider block">CVSS v3.1</span>
          <span className="text-xs font-mono font-bold" style={{ color }}>
            MAX {safeCvss.toFixed(1)}
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full h-1.5 rounded-full bg-obsidian-700 overflow-hidden mb-3.5">
        <div
          className="h-full transition-all duration-500 rounded-full"
          style={{ width: `${Math.max(5, score)}%`, backgroundColor: color }}
        />
      </div>

      {/* Status Alert Banner */}
      <div
        className={`px-3 py-2 rounded-md mb-3 flex items-center gap-2 text-xs font-medium ${
          isPassed
            ? "bg-emerald-950/25 border border-emerald-500/30 text-emerald-400"
            : "bg-red-950/25 border border-red-500/30 text-red-400"
        }`}
      >
        {isPassed ? (
          <>
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>ALL CHECKS PASSED — 100% Zero-Noise AST Verified</span>
          </>
        ) : (
          <>
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span>MERGE BLOCKED — {criticalCount} Critical Exploit(s) Detected</span>
          </>
        )}
      </div>

      {/* Compact Export Action Bar */}
      <div className="grid grid-cols-3 gap-2">
        <button
          onClick={() => onDownloadReport("soc2")}
          className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-[11px] font-medium text-slateText-secondary hover:text-slateText-primary transition-colors"
        >
          <FileText className="w-3.5 h-3.5 text-kavachGold" />
          <span>SOC 2 Report</span>
        </button>

        <button
          onClick={() => onDownloadReport("json")}
          className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-[11px] font-medium text-slateText-secondary hover:text-slateText-primary transition-colors"
        >
          <Download className="w-3.5 h-3.5 text-kavachEmerald" />
          <span>JSON Audit</span>
        </button>

        <button
          onClick={() => onDownloadReport("summary")}
          className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-obsidian-800 hover:bg-obsidian-700 border border-obsidian-700 text-[11px] font-medium text-slateText-secondary hover:text-slateText-primary transition-colors"
        >
          <FileText className="w-3.5 h-3.5 text-blue-400" />
          <span>Summary (.md)</span>
        </button>
      </div>
    </div>
  );
}
