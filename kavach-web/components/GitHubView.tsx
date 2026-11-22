"use client";

import React, { useState } from "react";
import { GitPullRequest, Copy, Check, Terminal, Code2, ShieldAlert } from "lucide-react";

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
    <div className="flex-1 p-6 lg:p-8 overflow-y-auto space-y-6 max-w-5xl mx-auto font-sans">
      {/* Title */}
      <div className="pb-4 border-b border-white/[0.08]">
        <h2 className="text-xl font-bold text-white tracking-tight font-sans">
          CI/CD Automation, GitHub Action Gate & Developer Extensions
        </h2>
        <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
          Block critical CWE vulnerabilities and credential leaks before they ever merge into production.
        </p>
      </div>

      {/* 3-Line GitHub Action Card */}
      <div className="rounded-xl bg-[#111114] border border-white/[0.08] overflow-hidden card-top-shine">
        <div className="p-3.5 bg-white/[0.02] border-b border-white/[0.08] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white font-mono">
              .github/workflows/kavach.yml
            </h3>
          </div>
          <button
            onClick={() => handleCopy(actionYaml, setCopiedAction)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-zinc-300 hover:text-white text-xs transition-all active:scale-[0.98]"
          >
            {copiedAction ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-medium">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-zinc-400" />
                <span>Copy YAML</span>
              </>
            )}
          </button>
        </div>
        <div className="p-4 bg-[#09090B] font-mono text-xs text-zinc-300 overflow-x-auto leading-relaxed">
          <pre>{actionYaml}</pre>
        </div>
      </div>

      {/* Two Column: VS Code Extension & CLI */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* VS Code Extension */}
        <div className="p-5 rounded-xl bg-[#111114] border border-white/[0.08] flex flex-col justify-between space-y-4 card-top-shine">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-emerald-400" />
                <span>VS Code Extension (v1.0.0)</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                Lightbulb Quick-Fix
              </span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed mb-3">
              Get sub-16ms AST diagnostics and 1-click surgical healing directly inside your IDE with <code className="text-zinc-200">Ctrl+.</code> lightbulb fixes.
            </p>
            <div className="p-2.5 rounded bg-[#09090B] border border-white/[0.08] font-mono text-[11px] text-zinc-300">
              <code>code --install-extension kavach-ai-1.0.0.vsix</code>
            </div>
          </div>
          <button
            onClick={() => handleCopy(vscodeSnippet, setCopiedVSCode)}
            className="w-full py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-zinc-200 border border-white/[0.08] text-xs font-medium flex items-center justify-center gap-1.5 transition-all active:scale-[0.98]"
          >
            {copiedVSCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
            <span>{copiedVSCode ? "Copied Command" : "Copy Install Command"}</span>
          </button>
        </div>

        {/* Local CLI */}
        <div className="p-5 rounded-xl bg-[#111114] border border-white/[0.08] flex flex-col justify-between space-y-4 card-top-shine">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Kavach AST CLI</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-medium">
                Zero Cloud Dependency
              </span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed mb-3">
              Run air-gapped security audits in local pre-commit hooks or local developer shells.
            </p>
            <div className="p-2.5 rounded bg-[#09090B] border border-white/[0.08] font-mono text-[11px] text-zinc-300">
              <code>pip install kavach-ai &amp;&amp; kavach scan .</code>
            </div>
          </div>
          <button
            onClick={() => handleCopy(cliSnippet, setCopiedCLI)}
            className="w-full py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-zinc-200 border border-white/[0.08] text-xs font-medium flex items-center justify-center gap-1.5 transition-all active:scale-[0.98]"
          >
            {copiedCLI ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
            <span>{copiedCLI ? "Copied CLI Guide" : "Copy CLI Commands"}</span>
          </button>
        </div>
      </div>

      {/* GitHub PR Bot Demo Simulation Card */}
      <div className="rounded-xl bg-[#111114] border border-white/[0.08] p-5 space-y-3 card-top-shine">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
            <span className="text-xs font-semibold text-white">PR Bot Simulation: Merge Blocked</span>
          </div>
          <span className="text-xs font-mono text-zinc-500">Pull Request #42 • payment_service.py</span>
        </div>
        <div className="p-3.5 rounded-lg bg-[#09090B] border border-red-500/20 space-y-2 text-xs">
          <div className="font-medium text-red-400 flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>Kavach AI Security Gate: 1 Critical Vulnerability Detected (CWE-89)</span>
          </div>
          <p className="text-zinc-400 leading-relaxed text-[11.5px]">
            Taint propagation found in line 14: User supplied parameter <code className="text-zinc-200">merchant_id</code> reaches raw SQL query without parameterization.
          </p>
          <div className="text-[11px] text-emerald-400 font-mono bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
            1-Click Surgical Patch Ready: Parameterized query replacement prepared.
          </div>
        </div>
      </div>
    </div>
  );
}
