"use client";

import React from "react";
import { Shield, ExternalLink, Sparkles, CheckCircle2 } from "lucide-react";

export default function Header() {
  return (
    <header className="border-b border-obsidian-700 bg-obsidian-900 px-6 py-3.5 flex items-center justify-between select-none">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-obsidian-800 border border-obsidian-700 text-kavachEmerald">
          <Shield className="w-5 h-5 fill-kavachEmerald/20" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-base tracking-tight text-slateText-primary font-mono">
              KAVACH <span className="text-kavachEmerald">AI</span>
            </span>
            <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-obsidian-800 border border-obsidian-700 text-slateText-secondary tracking-wider">
              v1.5.0
            </span>
          </div>
          <p className="text-[11px] text-slateText-muted hidden sm:block">
            Sub-16ms AST Pre-Merge Security Gate & Self-Healing Engine
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Status Pill */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-obsidian-850 border border-obsidian-700 text-[11.5px] text-slateText-secondary">
          <span className="w-2 h-2 rounded-full bg-kavachEmerald animate-pulse"></span>
          <span>Engine: 100% Operational</span>
          <span className="text-obsidian-600">•</span>
          <span className="text-slateText-muted">0.00% Telemetry Retention</span>
        </div>

        {/* GitHub link */}
        <a
          href="https://github.com/rajrajak99/kavach-ai"
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 text-xs font-medium text-slateText-secondary hover:text-slateText-primary px-3 py-1.5 rounded-md hover:bg-obsidian-800 transition-colors"
        >
          <span>GitHub</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </a>

        {/* Enterprise Sign In */}
        <button
          onClick={() => alert("Enterprise CISO Console active in demo mode.")}
          className="text-xs font-semibold px-3.5 py-1.5 rounded-md bg-kavachGold text-obsidian-950 hover:bg-kavachGold-hover transition-colors shadow-sm"
        >
          Enterprise Portal
        </button>
      </div>
    </header>
  );
}
