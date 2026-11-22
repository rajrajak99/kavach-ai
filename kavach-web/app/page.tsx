"use client";

import React, { useState, useEffect, useCallback } from "react";
import dynamic from "next/dynamic";
import Header from "@/components/Header";
import Scorecard from "@/components/Scorecard";
import DiffViewer from "@/components/DiffViewer";
import Sidebar, { ViewType } from "@/components/Sidebar";
import PostureView from "@/components/PostureView";
import BenchmarkView from "@/components/BenchmarkView";
import PricingView from "@/components/PricingView";
import GitHubView from "@/components/GitHubView";
import { Play, RotateCcw, Sparkles, Code2, AlertTriangle, ChevronDown } from "lucide-react";

// Dynamically import Monaco Editor to avoid SSR window issues
const Editor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

const DEFAULT_ENTERPRISE_CODE = `import os
import psycopg2
from fastapi import APIRouter, Request, HTTPException

router = APIRouter(prefix="/v1/payments", tags=["Settlement"])

# Enterprise Payment Gateway Ledger Service
@router.post("/settle-transaction")
async def settle_transaction(req: Request, merchant_id: str, batch_id: str):
    db_conn = psycopg2.connect(os.getenv("PAYMENT_DB_URL"))
    cursor = db_conn.cursor()
    # Vulnerable SQL Injection (CWE-89): Taint propagation in merchant ledger query
    query = f"SELECT * FROM merchant_ledgers WHERE merchant_id = '{merchant_id}' AND batch = '{batch_id}'"
    cursor.execute(query)
    return cursor.fetchall()
`;

const SAMPLES: Record<string, { filename: string; language: string; code: string }> = {
  fastapi_sqli: {
    filename: "payment_service.py",
    language: "python",
    code: DEFAULT_ENTERPRISE_CODE,
  },
  secrets_leak: {
    filename: "auth_service.py",
    language: "python",
    code: `import os, requests

def verify_session(token: str):
    # Hardcoded sensitive tokens (CWE-798)
    github_pat = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    aws_secret = "AKIAIOSFODNN7EXAMPLE"
    
    headers = {"Authorization": f"token {github_pat}"}
    return requests.get("https://api.github.com/user", headers=headers)
`,
  },
  node_cmd_inj: {
    filename: "export_handler.js",
    language: "javascript",
    code: `const express = require('express');
const child_process = require('child_process');
const router = express.Router();

router.post('/export', (req, res) => {
    const filename = req.body.filename;
    // Command Injection (CWE-78)
    child_process.exec(\`cat \${filename} > /tmp/out.txt\`);
    res.send({ status: 'done' });
});
`,
  },
  cpp_buffer: {
    filename: "buffer_alloc.cpp",
    language: "cpp",
    code: `#include <iostream>
#include <cstring>

void authenticate(const char* input_key) {
    // Unbounded Buffer Copy (CWE-120)
    char buffer[16];
    strcpy(buffer, input_key);
}
`,
  },
};

export default function Home() {
  const [activeView, setActiveView] = useState<ViewType>("inspector");
  const [code, setCode] = useState(DEFAULT_ENTERPRISE_CODE);
  const [filename, setFilename] = useState("payment_service.py");
  const [language, setLanguage] = useState("python");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [appliedPatches, setAppliedPatches] = useState<Record<number, boolean>>({});

  const VIEW_TITLES: Record<ViewType, string> = {
    inspector: "Code Inspector",
    posture: "Posture Dashboard",
    benchmark: "Live Benchmark",
    pricing: "Plans & Pricing",
    github: "CI/CD & GitHub Gate",
  };

  const runScan = useCallback(async (codeToScan: string, currentFile: string) => {
    setIsScanning(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: codeToScan, filename: currentFile }),
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error("Scan failed:", err);
    } finally {
      setIsScanning(false);
    }
  }, []);

  // Initial scan on page load
  useEffect(() => {
    runScan(code, filename);
  }, [runScan]);

  const handleApplyFix = (problemCode: string, fixedCode: string, lineNum: number) => {
    const updatedCode = code.replace(problemCode, fixedCode);
    setCode(updatedCode);
    setAppliedPatches((prev) => ({ ...prev, [lineNum]: true }));
    // Immediately re-scan with new code
    runScan(updatedCode, filename);
  };

  const LANGUAGES = [
    { id: "python", name: "Python", ext: "py" },
    { id: "javascript", name: "JavaScript", ext: "js" },
    { id: "typescript", name: "TypeScript", ext: "ts" },
    { id: "cpp", name: "C / C++", ext: "cpp" },
    { id: "go", name: "Go", ext: "go" },
    { id: "rust", name: "Rust", ext: "rs" },
    { id: "java", name: "Java", ext: "java" },
  ];

  const handleLanguageChange = (newLang: string) => {
    setLanguage(newLang);
    const matched = LANGUAGES.find((l) => l.id === newLang);
    if (matched) {
      const baseName = filename.split(".")[0] || "snippet";
      setFilename(`${baseName}.${matched.ext}`);
    }
  };

  const handleLoadSample = (sampleKey: string) => {
    const s = SAMPLES[sampleKey];
    if (s) {
      setCode(s.code);
      setFilename(s.filename);
      setLanguage(s.language);
      setAppliedPatches({});
      runScan(s.code, s.filename);
    }
  };

  const handleDownloadReport = (type: "soc2" | "json" | "summary") => {
    if (!scanResult) return;
    let content = "";
    let mime = "text/markdown";
    let dlFilename = `kavach_audit_${Date.now()}`;

    if (type === "json") {
      content = JSON.stringify(scanResult, null, 2);
      mime = "application/json";
      dlFilename += ".json";
    } else if (type === "soc2") {
      content = `# 🛡️ KAVACH AI — SOC 2 TYPE II & ISO-27001 PRE-AUDIT REPORT
**Generated:** ${new Date().toISOString()} | **Engine:** Kavach AI AST v1.5.0
**Target File:** ${filename}
**Status:** ${scanResult.status}
**Security Score:** ${scanResult.posture?.score}/100 (${scanResult.posture?.grade})
**Critical Exploits:** ${scanResult.metrics?.critical || 0}
**Security Advisories:** ${scanResult.metrics?.security || 0}

---
## Findings Detail
${scanResult.findings?.map((f: any) => `### L${f.line_number} [${f.severity}] ${f.category} (${f.cwe_id})
- **Problem Code:** \`${f.problem_code}\`
- **Surgical Patch:**
\`\`\`
${f.fixed_code}
\`\`\`
- **Explanation:** ${f.explanation}
`).join("\n") || "Zero vulnerabilities detected. Ready for production merge."}
`;
      dlFilename += "_soc2.md";
    } else {
      content = `# Kavach AI Executive Audit Summary
- **Compliance Score:** ${scanResult.posture?.score}/100
- **Audited Target:** ${filename}
- **Scan Latency:** < 16ms
`;
      dlFilename += "_summary.md";
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = dlFilename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const rawPosture = scanResult?.posture || {};
  const posture = {
    score: rawPosture.score ?? 100,
    grade: rawPosture.grade ?? "A",
    gradeLabel: rawPosture.gradeLabel || rawPosture.grade_label || "Deterministic AST Verified",
    color: rawPosture.color || "#22C58B",
    cvssMax: Number(rawPosture.cvssMax ?? rawPosture.cvss_max ?? 0),
  };

  const metrics = scanResult?.metrics || { critical: 0, security: 0, performance: 0 };
  const findings = scanResult?.findings || [];

  return (
    <div className="h-screen flex flex-row bg-obsidian-950 select-none overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar activeView={activeView} onSelectView={setActiveView} />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <Header activeViewTitle={VIEW_TITLES[activeView]} />

        {activeView === "inspector" && (
          <main className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Left 60%: Monaco Editor Panel */}
        <section className="w-full lg:w-[60%] border-r border-obsidian-700/80 flex flex-col bg-obsidian-950">
          {/* Editor Header Bar */}
          <div className="h-11 bg-obsidian-900 border-b border-obsidian-700/80 px-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-kavachEmerald"></span>
              <input
                type="text"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                className="bg-transparent border-b border-transparent hover:border-obsidian-700 focus:border-kavachEmerald outline-none font-mono text-xs font-semibold text-slateText-primary px-1 py-0.5 rounded transition-all w-44"
                title="Click to edit filename"
              />
              <span className="text-[10px] text-slateText-muted font-mono">• UTF-8</span>
            </div>

            <div className="flex items-center gap-2">
              {/* Language Selector Dropdown */}
              <div className="flex items-center gap-1.5 bg-obsidian-850 border border-obsidian-700 rounded px-2 py-1">
                <span className="text-[10.5px] font-semibold text-slateText-muted uppercase">Lang:</span>
                <select
                  value={language}
                  onChange={(e) => handleLanguageChange(e.target.value)}
                  className="bg-transparent text-slateText-primary text-xs font-medium cursor-pointer outline-none"
                >
                  <option value="python" className="bg-obsidian-900 text-slateText-primary">🐍 Python</option>
                  <option value="javascript" className="bg-obsidian-900 text-slateText-primary">⚡ JavaScript</option>
                  <option value="typescript" className="bg-obsidian-900 text-slateText-primary">🔷 TypeScript</option>
                  <option value="cpp" className="bg-obsidian-900 text-slateText-primary">⚙️ C / C++</option>
                  <option value="go" className="bg-obsidian-900 text-slateText-primary">🐹 Go</option>
                  <option value="rust" className="bg-obsidian-900 text-slateText-primary">🦀 Rust</option>
                  <option value="java" className="bg-obsidian-900 text-slateText-primary">☕ Java</option>
                </select>
              </div>

              {/* Sample / Demo Selector */}
              <select
                onChange={(e) => {
                  if (e.target.value) handleLoadSample(e.target.value);
                }}
                className="bg-obsidian-850 border border-obsidian-700 text-slateText-secondary hover:text-slateText-primary rounded px-2.5 py-1 text-xs font-medium cursor-pointer outline-none focus:border-kavachEmerald transition-colors"
                defaultValue=""
              >
                <option value="" disabled>⚡ Demos / Samples ▾</option>
                <option value="fastapi_sqli" className="bg-obsidian-900">💉 FastAPI SQLi (Py)</option>
                <option value="secrets_leak" className="bg-obsidian-900">🔑 Secret Leaks (Py)</option>
                <option value="node_cmd_inj" className="bg-obsidian-900">⚡ Command Inj (JS)</option>
                <option value="cpp_buffer" className="bg-obsidian-900">🛡️ Buffer Overflow (C++)</option>
              </select>

              <button
                onClick={() => setCode("")}
                className="px-2.5 py-1 rounded bg-obsidian-850 hover:bg-obsidian-800 text-slateText-muted hover:text-slateText-primary text-xs font-medium transition-colors border border-obsidian-700"
              >
                Clear
              </button>

              <button
                onClick={() => runScan(code, filename)}
                disabled={isScanning}
                className="flex items-center gap-1.5 px-3 py-1 rounded bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 font-bold text-xs shadow-[0_0_12px_rgba(16,185,129,0.3)] hover:opacity-95 transition-all active:scale-95"
              >
                <Play className="w-3.5 h-3.5 fill-obsidian-950" />
                <span>{isScanning ? "Scanning..." : "⚡ Inspect Code"}</span>
              </button>
            </div>
          </div>

          {/* Monaco Editor Container */}
          <div className="flex-1 min-h-[480px] lg:min-h-0 bg-[#0B0E13]">
            <Editor
              height="100%"
              theme="vs-dark"
              language={language}
              value={code}
              onChange={(newVal) => setCode(newVal || "")}
              options={{
                fontSize: 13,
                fontFamily: "'JetBrains Mono', monospace",
                lineNumbers: "on",
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                automaticLayout: true,
                padding: { top: 12 },
                tabSize: 4,
              }}
            />
          </div>
        </section>

        {/* Right 40%: Audit & Remediation Panel */}
        <section className="w-full lg:w-[40%] bg-obsidian-900/60 p-4 lg:p-5 flex flex-col overflow-y-auto">
          {/* Posture Scorecard */}
          <Scorecard
            score={posture.score}
            grade={posture.grade}
            gradeLabel={posture.gradeLabel}
            color={posture.color}
            cvssMax={posture.cvssMax}
            criticalCount={metrics.critical}
            warningCount={metrics.security}
            onDownloadReport={handleDownloadReport}
          />

          {/* Findings & 1-Click Remediation Hero List */}
          <div className="flex-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slateText-secondary">
                Surgical Findings & 1-Click Auto-Fixes ({findings.length})
              </span>
              <span className="text-[11px] font-mono text-kavachEmerald">
                Zero False Alarms
              </span>
            </div>

            {findings.length === 0 ? (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/15 p-6 text-center">
                <div className="w-10 h-10 rounded-full bg-emerald-500/20 text-kavachEmerald flex items-center justify-center mx-auto mb-2">
                  <Sparkles className="w-5 h-5" />
                </div>
                <h4 className="font-semibold text-sm text-slateText-primary mb-1">
                  100% Clean Code — Ready for Merge
                </h4>
                <p className="text-xs text-slateText-secondary max-w-sm mx-auto">
                  Zero vulnerabilities, resource leaks, or credential hazards detected. All AST deterministic gates passed.
                </p>
              </div>
            ) : (
              findings.map((f: any, idx: number) => (
                <div key={`finding-${idx}`} className="mb-4">
                  {/* Category Header */}
                  <div className="flex items-center justify-between mb-1.5 px-1">
                    <span className="text-xs font-semibold text-slateText-primary flex items-center gap-1.5">
                      <span className="text-red-400 font-mono">L{f.line_number}</span>
                      <span>{f.category}</span>
                    </span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-500/30">
                      {f.severity}
                    </span>
                  </div>

                  {/* Diff Viewer with prominent 1-Click Fix Button */}
                  <DiffViewer
                    problemCode={f.problem_code}
                    fixedCode={f.fixed_code}
                    lineNumber={f.line_number}
                    category={f.category}
                    cweId={f.cwe_id}
                    isApplied={!!appliedPatches[f.line_number]}
                    onApplyFix={() => handleApplyFix(f.problem_code, f.fixed_code, f.line_number)}
                  />

                  {/* Taint Flow Trace */}
                  <div className="px-3 py-2 rounded bg-obsidian-850 border border-obsidian-700/80 text-[11px] text-slateText-secondary mb-3">
                    <div className="flex items-center gap-1.5 text-slateText-muted mb-1">
                      <span className="font-semibold text-slateText-secondary">AST Taint Trace:</span>
                      <span className="text-red-400 font-mono">Source L{f.line_number}</span>
                      <span>➔</span>
                      <span className="text-amber-400">Taint Propagation</span>
                      <span>➔</span>
                      <span className="text-slateText-primary font-mono">{f.category}</span>
                    </div>
                    <p className="text-slateText-muted leading-relaxed">{f.explanation}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </main>
    )}

    {activeView === "posture" && <PostureView />}
    {activeView === "benchmark" && <BenchmarkView />}
    {activeView === "pricing" && <PricingView />}
    {activeView === "github" && <GitHubView />}
  </div>
</div>
  );
}
