"use client";

import React, { useState } from "react";
import { GitPullRequest, Copy, Check, Terminal, ExternalLink, Code2, ShieldAlert, Cpu } from "lucide-react";

export default function GitHubView() {
  const [copiedAction, setCopiedAction] = useState(false);
  const [copiedCLI, setCopiedCLI] = useState(false);
  const [copiedVSCode, setCopiedVSCode] = useState(false);

  const actionYaml = `name: Kavach Security Gate
on: [pull_request, push]
jobs:
  kavach-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rajrajak99/kavach-ai@v1
        with:
          github-token: \${{ secrets.GITHUB_TOKEN }}
          fail-on: critical`;

  const cliSnippet = `# 1. Install Kavach AI via pip
pip install kavach-ai

# 2. Run AST Audit on your current repository
kavach scan .

# 3. Apply 1-Click Surgical Self-Healing
kavach heal . --verify-tests`;

  const vscodeSnippet = `# Install the official Kavach AI Extension:
code --install-extension kavach-ai-1.0.0.vsix`;

  const timersRef = React.useRef<NodeJS.Timeout[]>([]);

  React.useEffect(() => {
    return () => {
      timersRef.current.forEach(clearTimeout);
    };
  }, []);

  const handleCopy = async (text: string, setter: (v: boolean) => void) => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        setter(true);
        const t = setTimeout(() => setter(false), 2000);
        timersRef.current.push(t);
      }
    } catch (e) {
      console.warn("Clipboard access denied or unavailable", e);
    }
  };

  return (
    <div className="flex-1 p-6 lg:p-8 overflow-y-auto space-y-6 max-w-5xl mx-auto">
      {/* Title */}
      <div className="pb-4 border-b border-obsidian-700/80">
        <h2 className="text-xl font-bold text-slateText-primary tracking-tight">
          CI/CD Automation, GitHub Action Gate & Developer Extensions
        </h2>
        <p className="text-xs text-slateText-muted mt-1">
          Block critical CWE vulnerabilities and credential leaks before they ever merge into production.
        </p>
      </div>

      {/* 3-Line GitHub Action Card */}
      <div className="rounded-xl bg-obsidian-850 border border-obsidian-700 overflow-hidden shadow-sm">
        <div className="p-4 bg-obsidian-800 border-b border-obsidian-700 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-kavachEmerald" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slateText-primary font-mono">
              .github/workflows/kavach.yml
            </h3>
          </div>
          <button
            onClick={() => handleCopy(actionYaml, setCopiedAction)}
            className="flex items-center gap-1.5 px-3 py-1 rounded bg-obsidian-900 border border-obsidian-700 text-slateText-secondary hover:text-slateText-primary text-xs transition-colors"
          >
            {copiedAction ? (
              <>
                <Check className="w-3.5 h-3.5 text-kavachEmerald" />
                <span className="text-kavachEmerald font-medium">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Workflow YAML</span>
              </>
            )}
          </button>
        </div>
        <div className="p-4 bg-obsidian-950 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed">
          <pre>{actionYaml}</pre>
        </div>
      </div>

      {/* Two Column: VS Code Extension & CLI */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* VS Code Extension */}
        <div className="p-5 rounded-xl bg-obsidian-850 border border-obsidian-700 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slateText-primary flex items-center gap-2">
                <Code2 className="w-4 h-4 text-kavachEmerald" />
                <span>VS Code Extension (v1.0.0)</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-kavachEmerald border border-emerald-500/30">
                Lightbulb Quick-Fix
              </span>
            </div>
            <p className="text-xs text-slateText-muted leading-relaxed mb-3">
              Get sub-16ms AST diagnostics and 1-click surgical healing directly inside your IDE with <code className="text-slateText-primary">Ctrl+.</code> lightbulb fixes.
            </p>
            <div className="p-2.5 rounded bg-obsidian-950 border border-obsidian-700 font-mono text-[11px] text-slate-300">
              <code>code --install-extension kavach-ai-1.0.0.vsix</code>
            </div>
          </div>
          <button
            onClick={() => handleCopy(vscodeSnippet, setCopiedVSCode)}
            className="w-full py-2 rounded-lg bg-obsidian-800 hover:bg-obsidian-750 text-slateText-primary border border-obsidian-700 text-xs font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            {copiedVSCode ? <Check className="w-3.5 h-3.5 text-kavachEmerald" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedVSCode ? "Copied Command!" : "Copy Install Command"}</span>
          </button>
        </div>

        {/* Local CLI */}
        <div className="p-5 rounded-xl bg-obsidian-850 border border-obsidian-700 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slateText-primary flex items-center gap-2">
                <Terminal className="w-4 h-4 text-kavachCyan" />
                <span>Kavach AST CLI</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/15 text-kavachCyan border border-sky-500/30">
                Zero Cloud Dependency
              </span>
            </div>
            <p className="text-xs text-slateText-muted leading-relaxed mb-3">
              Run air-gapped security audits in local pre-commit hooks or local developer shells.
            </p>
            <div className="p-2.5 rounded bg-obsidian-950 border border-obsidian-700 font-mono text-[11px] text-slate-300">
              <code>pip install kavach-ai && kavach scan .</code>
            </div>
          </div>
          <button
            onClick={() => handleCopy(cliSnippet, setCopiedCLI)}
            className="w-full py-2 rounded-lg bg-obsidian-800 hover:bg-obsidian-750 text-slateText-primary border border-obsidian-700 text-xs font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            {copiedCLI ? <Check className="w-3.5 h-3.5 text-kavachEmerald" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCLI ? "Copied CLI Guide!" : "Copy CLI Commands"}</span>
          </button>
        </div>
      </div>

      {/* GitHub PR Bot Demo Simulation Card */}
      <div className="rounded-xl bg-obsidian-850 border border-obsidian-700 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse"></span>
            <span className="text-xs font-bold text-slateText-primary">PR Bot Simulation: Merge Blocked</span>
          </div>
          <span className="text-xs font-mono text-slateText-muted">Pull Request #42 • payment_service.py</span>
        </div>
        <div className="p-3.5 rounded-lg bg-obsidian-950 border border-red-500/30 space-y-2 text-xs">
          <div className="font-semibold text-red-400 flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4" />
            <span>Kavach AI Security Gate: 1 Critical Vulnerability Detected (CWE-89)</span>
          </div>
          <p className="text-slateText-muted">
            Taint propagation found in line 14: User supplied parameter <code className="text-slateText-primary">merchant_id</code> reaches raw SQL query without parameterization.
          </p>
          <div className="text-[11px] text-kavachEmerald font-mono bg-kavachEmerald/10 p-2 rounded border border-kavachEmerald/25">
            ⚡ 1-Click Surgical Patch Ready: Parameterized query replacement prepared.
          </div>
        </div>
      </div>
    </div>
  );
}
