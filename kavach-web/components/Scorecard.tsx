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
  color = "#10B981",
  cvssMax = 0,
  criticalCount = 0,
  warningCount = 0,
  onDownloadReport,
}: ScorecardProps) {
  const clampedScore = Math.min(100, Math.max(0, score));
  const isPassed = criticalCount === 0;
  const safeCvss = Number(cvssMax) || 0;

  return (
    <div className="bg-[#111114] border border-white/[0.08] rounded-xl p-4 mb-4 relative overflow-hidden card-top-shine">
      {/* Top Score Row */}
      <div className="flex items-center justify-between mb-3.5">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center font-bold text-lg font-mono tracking-tight"
            style={{
              backgroundColor: `${color}14`,
              color: color,
              border: `1px solid ${color}30`,
            }}
          >
            {grade}
          </div>
          <div>
            <div className="text-xs font-medium text-white flex items-center gap-2">
              <span className="font-mono tabular-nums">Security Health: {clampedScore}/100</span>
              <span
                className="text-[10px] px-1.5 py-0.2 rounded font-mono font-semibold"
                style={{ backgroundColor: `${color}14`, color: color, border: `1px solid ${color}25` }}
              >
                {isPassed ? (warningCount > 0 ? "WARNING" : "PASS") : "BLOCKED"}
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 mt-0.5">{gradeLabel}</p>
          </div>
        </div>

        <div className="text-right">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono block">CVSS v3.1</span>
          <span className="text-xs font-mono font-bold tabular-nums" style={{ color }}>
            MAX {safeCvss.toFixed(1)}
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full h-1 rounded-full bg-white/[0.06] overflow-hidden mb-3">
        <div
          className="h-full transition-all duration-500 rounded-full"
          style={{ width: `${Math.max(4, Math.min(100, clampedScore))}%`, backgroundColor: color }}
        />
      </div>

      {/* Status Alert Banner */}
      <div
        className={`px-3 py-2 rounded-lg mb-3 flex items-center gap-2 text-xs font-medium ${
          !isPassed
            ? "bg-red-500/10 border border-red-500/20 text-red-400"
            : warningCount > 0
            ? "bg-amber-500/10 border border-amber-500/20 text-amber-400"
            : "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
        }`}
      >
        {!isPassed ? (
          <>
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span>MERGE BLOCKED — {criticalCount} Critical Exploit(s) Detected</span>
          </>
        ) : warningCount > 0 ? (
          <>
            <AlertOctagon className="w-4 h-4 text-amber-400 shrink-0" />
            <span>PASSED WITH ADVISORY — 0 Critical, {warningCount} Non-blocking Issue(s)</span>
          </>
        ) : (
          <>
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>ALL CHECKS PASSED — 100% Zero-Noise AST Verified</span>
          </>
        )}
      </div>

      {/* Compact Export Action Bar */}
      <div className="grid grid-cols-3 gap-2">
        <button
          onClick={() => onDownloadReport("soc2")}
          className="flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-[11px] font-medium text-zinc-300 hover:text-white transition-all"
        >
          <FileText className="w-3 h-3 text-amber-400" />
          <span>SOC 2 Report</span>
        </button>

        <button
          onClick={() => onDownloadReport("json")}
          className="flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-[11px] font-medium text-zinc-300 hover:text-white transition-all"
        >
          <Download className="w-3 h-3 text-emerald-400" />
          <span>JSON Audit</span>
        </button>

        <button
          onClick={() => onDownloadReport("summary")}
          className="flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-[11px] font-medium text-zinc-300 hover:text-white transition-all"
        >
          <FileText className="w-3 h-3 text-sky-400" />
          <span>Summary (.md)</span>
        </button>
      </div>
    </div>
  );
}
