"use client";

import React from "react";
import { ExternalLink, Zap } from "lucide-react";

interface HeaderProps {
  activeViewTitle?: string;
}

export default function Header({ activeViewTitle = "Code Inspector" }: HeaderProps) {
  return (
    <header className="h-[52px] border-b border-white/[0.08] bg-[#09090B]/80 backdrop-blur-md px-5 flex items-center justify-between select-none shrink-0 z-20">
      {/* Breadcrumb & Environment Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-xs">
          <span className="font-mono text-zinc-500 hover:text-zinc-400 transition-colors">Kavach AI</span>
          <span className="text-zinc-600">/</span>
          <span className="font-medium text-[#FAFAFA] tracking-tight">{activeViewTitle}</span>
        </div>

        <div className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-white/[0.04] border border-white/[0.08] text-[10.5px] text-zinc-400 font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.5)]"></span>
          <span>Air-Gapped Sandbox</span>
        </div>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-2.5">
        {/* Latency Pill */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[11px] text-emerald-400 font-mono font-medium">
          <Zap className="w-3 h-3 fill-emerald-400 text-emerald-400" />
          <span>&lt; 16ms AST</span>
        </div>

        {/* GitHub Star */}
        <a
          href="https://github.com/rajrajak99/kavach-ai"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-medium text-zinc-300 hover:text-white px-2.5 py-1 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] transition-all"
        >
          <span>Star on GitHub</span>
          <ExternalLink className="w-3 h-3 text-zinc-500" />
        </a>

        {/* Enterprise Portal CTA */}
        <a
          href="https://github.com/rajrajak99/kavach-ai#enterprise"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs font-semibold px-3 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-sm transition-all active:scale-[0.98] inline-flex items-center gap-1"
        >
          Enterprise Portal
        </a>
      </div>
    </header>
  );
}
