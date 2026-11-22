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
import MultiFileProjectView from "@/components/MultiFileProjectView";
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
  const [inspectorMode, setInspectorMode] = useState<"snippet" | "project">("snippet");
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

  const CLEAN_POSTURE = {
    score: 100,
    grade: "A",
    gradeLabel: "Deterministic AST Verified",
    color: "#10B981",
    cvssMax: 0,
  };

  const CLEAN_SCAN_RESULT = {
    status: "PASSED",
    metrics: { critical: 0, security: 0, performance: 0, total: 0 },
    findings: [],
    posture: CLEAN_POSTURE,
  };

  const runScan = useCallback(async (codeToScan: string, currentFile: string) => {
    if (!codeToScan || !codeToScan.trim()) {
      setScanResult(CLEAN_SCAN_RESULT);
      setAppliedPatches({});
      setIsScanning(false);
      return;
    }
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

  const handleClear = () => {
    setCode("");
    setAppliedPatches({});
    setScanResult(CLEAN_SCAN_RESULT);
  };

  // Initial scan on page load
  useEffect(() => {
    runScan(code, filename);
  }, [runScan]);

  const [currentTier, setCurrentTier] = useState("FREE");

  const handleApplyFix = (problemCode: string, fixedCode: string, lineNum: number) => {
    const lines = code.split("\n");
    let updatedCode = "";
    const targetIdx = lineNum - 1;
    const cleanProb = problemCode.trim();

    if (targetIdx >= 0 && targetIdx < lines.length && lines[targetIdx].includes(cleanProb)) {
      lines[targetIdx] = lines[targetIdx].replace(cleanProb, fixedCode);
      updatedCode = lines.join("\n");
    } else {
      const probLines = cleanProb.split("\n");
      let matched = false;
      if (targetIdx >= 0 && targetIdx + probLines.length <= lines.length) {
        const sliceStr = lines.slice(targetIdx, targetIdx + probLines.length).map(l => l.trim()).join("\n");
        if (sliceStr.includes(cleanProb)) {
          const origIndent = lines[targetIdx].match(/^\s*/)?.[0] || "";
          const fixedIndented = fixedCode.split("\n").map(fl => origIndent + fl.trimStart()).join("\n");
          lines.splice(targetIdx, probLines.length, fixedIndented);
          updatedCode = lines.join("\n");
          matched = true;
        }
      }
      if (!matched) {
        updatedCode = code.replace(cleanProb, fixedCode);
        if (updatedCode === code) {
          updatedCode = code.replace(problemCode, fixedCode);
        }
      }
    }

    if (updatedCode !== code) {
      setCode(updatedCode);
      setAppliedPatches((prev) => ({ ...prev, [lineNum]: true }));
      runScan(updatedCode, filename);
    }
  };

  const LANGUAGES = [
    { id: "python", name: "Python", ext: "py" },
    { id: "javascript", name: "JavaScript", ext: "js" },
    { id: "typescript", name: "TypeScript", ext: "ts" },
    { id: "cpp", name: "C / C++", ext: "cpp" },
    { id: "go", name: "Go", ext: "go" },
    { id: "dockerfile", name: "Dockerfile", ext: "dockerfile" },
    { id: "terraform", name: "Terraform", ext: "tf" },
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

  const handleEditorWillMount = (monaco: any) => {
    monaco.editor.defineTheme("kavach-dark", {
      base: "vs-dark",
      inherit: true,
      rules: [],
      colors: {
        "editor.background": "#09090B",
        "editor.lineHighlightBackground": "#111114",
        "editorLineNumber.foreground": "#52525B",
        "editorLineNumber.activeForeground": "#FAFAFA",
        "editorGutter.background": "#09090B",
      },
    });
  };

  return (
    <div className="h-screen flex flex-row bg-[#09090B] select-none overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        activeView={activeView}
        onSelectView={setActiveView}
        licenseTier={currentTier}
        onTierChange={setCurrentTier}
      />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <Header activeViewTitle={VIEW_TITLES[activeView]} />

        {activeView === "inspector" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Mode Switcher Bar */}
            <div className="h-10 bg-[#111114] border-b border-white/[0.08] px-4 sm:px-6 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono text-zinc-500 uppercase tracking-wider text-[10px]">Workspace Mode:</span>
                <span className="font-medium text-[#FAFAFA] font-mono text-xs">
                  {inspectorMode === "snippet" ? "Single File / Monaco Editor" : "Multi-File Project & SCA Matrix"}
                </span>
              </div>

              {/* Segmented Control */}
              <div className="flex items-center p-0.5 rounded-lg bg-white/[0.04] border border-white/[0.08] text-xs">
                <button
                  onClick={() => setInspectorMode("snippet")}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                    inspectorMode === "snippet"
                      ? "bg-white/[0.08] text-white shadow-sm font-semibold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  Single File / Snippet
                </button>
                <button
                  onClick={() => setInspectorMode("project")}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                    inspectorMode === "project"
                      ? "bg-white/[0.08] text-white shadow-sm font-semibold"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  Project / Multi-File (.zip)
                </button>
              </div>
            </div>

            {inspectorMode === "snippet" ? (
              <main className="flex-1 flex flex-col lg:flex-row overflow-hidden">
                {/* Left 60%: Monaco Editor Panel */}
                <section className="w-full lg:w-[60%] border-r border-white/[0.08] flex flex-col bg-[#09090B]">
                  {/* Editor Header Bar */}
                  <div className="h-10 bg-[#111114] border-b border-white/[0.08] px-4 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <input
                        type="text"
                        value={filename}
                        onChange={(e) => setFilename(e.target.value)}
                        className="bg-transparent border-b border-transparent hover:border-white/[0.15] focus:border-emerald-500/60 outline-none font-mono text-xs font-medium text-white px-1 py-0.5 rounded transition-all w-44"
                        title="Click to edit filename"
                      />
                      <span className="text-[10px] text-zinc-500 font-mono">• UTF-8</span>
                    </div>

                    <div className="flex items-center gap-2">
                      {/* Language Selector Dropdown */}
                      <div className="flex items-center gap-1.5 bg-[#09090B] border border-white/[0.08] rounded px-2 py-0.5">
                        <span className="text-[10px] font-mono text-zinc-500 uppercase">Lang:</span>
                        <select
                          value={language}
                          onChange={(e) => handleLanguageChange(e.target.value)}
                          className="bg-transparent text-zinc-300 text-xs font-medium cursor-pointer outline-none"
                        >
                          <option value="python" className="bg-[#111114] text-zinc-200">Python</option>
                          <option value="javascript" className="bg-[#111114] text-zinc-200">JavaScript</option>
                          <option value="typescript" className="bg-[#111114] text-zinc-200">TypeScript</option>
                          <option value="cpp" className="bg-[#111114] text-zinc-200">C / C++</option>
                          <option value="go" className="bg-[#111114] text-zinc-200">Go</option>
                          <option value="rust" className="bg-[#111114] text-zinc-200">Rust</option>
                          <option value="java" className="bg-[#111114] text-zinc-200">Java</option>
                        </select>
                      </div>

                      {/* Sample / Demo Selector */}
                      <select
                        onChange={(e) => {
                          if (e.target.value) handleLoadSample(e.target.value);
                        }}
                        className="bg-[#09090B] border border-white/[0.08] text-zinc-300 hover:text-white rounded px-2 py-0.5 text-xs font-medium cursor-pointer outline-none focus:border-emerald-500/50 transition-colors"
                        defaultValue=""
                      >
                        <option value="" disabled>Demos ▾</option>
                        <option value="fastapi_sqli" className="bg-[#111114]">FastAPI SQLi (Py)</option>
                        <option value="secrets_leak" className="bg-[#111114]">Secret Leaks (Py)</option>
                        <option value="node_cmd_inj" className="bg-[#111114]">Command Inj (JS)</option>
                        <option value="cpp_buffer" className="bg-[#111114]">Buffer Overflow (C++)</option>
                      </select>

                      <button
                        onClick={handleClear}
                        className="px-2 py-0.5 rounded bg-white/[0.04] hover:bg-white/[0.08] text-zinc-400 hover:text-zinc-200 text-xs font-medium transition-colors border border-white/[0.08]"
                      >
                        Clear
                      </button>

                      <button
                        onClick={() => runScan(code, filename)}
                        disabled={isScanning}
                        className="flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs shadow-sm transition-all active:scale-[0.98]"
                      >
                        <Play className="w-3 h-3 fill-zinc-950" />
                        <span>{isScanning ? "Scanning..." : "Inspect Code"}</span>
                      </button>
                    </div>
                  </div>

                  {/* Monaco Editor Container */}
                  <div className="flex-1 min-h-[480px] lg:min-h-0 bg-[#09090B]">
                    <Editor
                      height="100%"
                      theme="kavach-dark"
                      language={language}
                      value={code}
                      beforeMount={handleEditorWillMount}
                      onChange={(newVal) => {
                        const val = newVal || "";
                        setCode(val);
                        if (!val.trim()) {
                          setScanResult(CLEAN_SCAN_RESULT);
                          setAppliedPatches({});
                        }
                      }}
                      options={{
                        fontSize: 13,
                        fontFamily: "var(--font-mono), 'JetBrains Mono', monospace",
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
                <section className="w-full lg:w-[40%] bg-[#09090B] p-4 lg:p-5 flex flex-col overflow-y-auto">
                  {/* Posture Scorecard */}
                  <Scorecard
                    score={posture.score}
                    grade={posture.grade}
                    gradeLabel={posture.gradeLabel}
                    color={posture.color}
                    cvssMax={posture.cvssMax}
                    criticalCount={metrics.critical}
                    warningCount={metrics.security}
                    isEmpty={!code.trim()}
                    onDownloadReport={handleDownloadReport}
                  />

                  {/* Findings & 1-Click Remediation Hero List */}
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2.5">
                      <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                        Surgical Findings & 1-Click Auto-Fixes ({findings.length})
                      </span>
                      <span className="text-[11px] font-mono text-emerald-400">
                        Zero False Alarms
                      </span>
                    </div>

                    {!code.trim() ? (
                      <div className="rounded-xl border border-white/[0.08] bg-[#111114] p-6 text-center card-top-shine">
                        <div className="w-9 h-9 rounded-full bg-white/[0.04] text-zinc-400 flex items-center justify-center mx-auto mb-2 border border-white/[0.08]">
                          <Code2 className="w-4 h-4" />
                        </div>
                        <h4 className="font-semibold text-xs text-white mb-1">
                          Editor is Empty
                        </h4>
                        <p className="text-[11px] text-zinc-400 max-w-sm mx-auto leading-relaxed mb-3">
                          Paste your source code or select a demo sample from above to run instant AST inspection.
                        </p>
                        <div className="flex flex-wrap items-center justify-center gap-1.5">
                          <button
                            onClick={() => handleLoadSample("fastapi_sqli")}
                            className="text-[10.5px] font-mono px-2.5 py-1 rounded bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-zinc-300 transition-colors"
                          >
                            ⚡ FastAPI SQLi
                          </button>
                          <button
                            onClick={() => handleLoadSample("secrets_leak")}
                            className="text-[10.5px] font-mono px-2.5 py-1 rounded bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-zinc-300 transition-colors"
                          >
                            🔑 Secret Leaks
                          </button>
                          <button
                            onClick={() => handleLoadSample("node_cmd_inj")}
                            className="text-[10.5px] font-mono px-2.5 py-1 rounded bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-zinc-300 transition-colors"
                          >
                            ⚡ Command Inj
                          </button>
                        </div>
                      </div>
                    ) : findings.length === 0 ? (
                      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.04] p-6 text-center card-top-shine">
                        <div className="w-9 h-9 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center mx-auto mb-2 border border-emerald-500/20">
                          <Sparkles className="w-4 h-4" />
                        </div>
                        <h4 className="font-semibold text-xs text-white mb-1">
                          100% Clean Code — Ready for Merge
                        </h4>
                        <p className="text-[11px] text-zinc-400 max-w-sm mx-auto leading-relaxed">
                          Zero vulnerabilities, resource leaks, or credential hazards detected. All AST deterministic gates passed.
                        </p>
                      </div>
                    ) : (
                      findings.map((f: any, idx: number) => (
                        <div key={`finding-${idx}`} className="mb-4">
                          {/* Category Header */}
                          <div className="flex items-center justify-between mb-1.5 px-0.5">
                            <span className="text-xs font-medium text-white flex items-center gap-1.5">
                              <span className="text-zinc-400 font-mono bg-white/[0.04] px-1.5 py-0.2 rounded border border-white/[0.06] text-[10.5px]">
                                L{f.line_number}
                              </span>
                              <span>{f.category}</span>
                            </span>
                            <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded bg-red-500/10 text-red-400 border border-red-500/20">
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
                          <div className="px-3 py-2 rounded-lg bg-[#111114] border border-white/[0.08] text-[11px] text-zinc-300 mb-3">
                            <div className="flex items-center gap-1.5 text-zinc-400 mb-1 font-mono text-[10.5px]">
                              <span className="font-medium text-zinc-300">AST Taint Trace:</span>
                              <span className="text-red-400">Source L{f.line_number}</span>
                              <span className="text-zinc-600">➔</span>
                              <span className="text-amber-400">Propagation</span>
                              <span className="text-zinc-600">➔</span>
                              <span className="text-zinc-200">{f.cwe_id} Sink</span>
                            </div>
                            <p className="text-zinc-400 leading-relaxed text-[10.5px]">{f.explanation}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </section>
              </main>
            ) : (
              <MultiFileProjectView />
            )}
          </div>
        )}

        {activeView === "posture" && <PostureView />}
        {activeView === "benchmark" && <BenchmarkView />}
        {activeView === "pricing" && <PricingView />}
        {activeView === "github" && <GitHubView />}
      </div>
    </div>
  );
}
