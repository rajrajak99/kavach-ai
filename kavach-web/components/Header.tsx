"use client";

import React from "react";
import { Shield, ExternalLink, Sparkles, CheckCircle2 } from "lucide-react";

interface HeaderProps {
  activeViewTitle?: string;
}

export default function Header({ activeViewTitle = "Code Inspector" }: HeaderProps) {
  return (
    <header className="border-b border-obsidian-700 bg-obsidian-900/90 backdrop-blur-md px-6 py-2.5 flex items-center justify-between select-none shrink-0 z-10">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slateText-muted">Kavach AI</span>
          <span className="text-obsidian-600">/</span>
          <span className="text-xs font-bold text-slateText-primary">{activeViewTitle}</span>
          <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-obsidian-850 border border-obsidian-700 text-[10.5px] text-slateText-secondary font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-kavachEmerald"></span>
            Air-Gapped Sandbox
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Sub-16ms Pill */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-kavachEmerald/10 border border-kavachEmerald/25 text-[11px] text-kavachEmerald font-mono font-semibold">
          <span>⚡ Sub-16ms AST</span>
        </div>

        {/* GitHub link */}
        <a
          href="https://github.com/rajrajak99/kavach-ai"
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 text-xs font-medium text-slateText-secondary hover:text-slateText-primary px-2.5 py-1 rounded-md bg-obsidian-850 hover:bg-obsidian-800 border border-obsidian-700 transition-colors"
        >
          <span>★ Star 56</span>
          <ExternalLink className="w-3 h-3 text-slateText-muted" />
        </a>

        {/* Enterprise Portal */}
        <button
          onClick={() => alert("Enterprise CISO Console active in demo mode.")}
          className="text-xs font-bold px-3 py-1.5 rounded-md bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 hover:opacity-95 shadow-[0_0_12px_rgba(16,185,129,0.3)] transition-all active:scale-95"
        >
          Enterprise Portal
        </button>
      </div>
    </header>
  );
}
