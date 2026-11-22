"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Code2, 
  Activity, 
  BarChart3, 
  CreditCard, 
  GitBranch, 
  Lock, 
  User, 
  Copy,
  Check
} from "lucide-react";

export type ViewType = "inspector" | "posture" | "benchmark" | "pricing" | "github";

interface SidebarProps {
  activeView: ViewType;
  onSelectView: (v: ViewType) => void;
  licenseTier?: string;
  onTierChange?: (tier: string) => void;
}

export default function Sidebar({ activeView, onSelectView, licenseTier = "FREE", onTierChange }: SidebarProps) {
  const [authTab, setAuthTab] = useState<"pilot" | "key" | "signin">("pilot");
  const [pilotEmail, setPilotEmail] = useState("");
  const [keyInput, setKeyInput] = useState("");
  const [pilotSuccess, setPilotSuccess] = useState(false);
  const [keySuccess, setKeySuccess] = useState(false);
  const [keyError, setKeyError] = useState("");
  const [tier, setTier] = useState(licenseTier);
  const [copiedCli, setCopiedCli] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    try {
      const savedKey = localStorage.getItem("kavach_license_key");
      const savedTier = localStorage.getItem("kavach_license_tier");
      if (savedKey && savedTier) {
        setTier(savedTier);
        onTierChange?.(savedTier);
      }
    } catch (e) {
      // Storage unavailable or disabled in sandboxed iframe
    }
  }, [onTierChange]);

  const handleClaimPilot = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanEmail = pilotEmail.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
    if (!emailRegex.test(cleanEmail)) {
      setKeyError("Please enter a valid corporate email.");
      return;
    }
    setIsVerifying(true);
    setKeyError("");
    try {
      const res = await fetch("/api/license", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "claim_pilot", email: cleanEmail }),
      });
      const data = await res.json();
      if (res.ok && data.valid) {
        try {
          localStorage.setItem("kavach_license_key", data.key);
          localStorage.setItem("kavach_license_tier", data.tier);
        } catch (_) {}
        setPilotSuccess(true);
        setTier(data.tier);
        onTierChange?.(data.tier);
        setTimeout(() => setPilotSuccess(false), 4000);
      } else {
        setKeyError(data.error || "Failed to provision VIP pilot license.");
      }
    } catch (err) {
      setKeyError("Network error validating pilot license.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleActivateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanKey = keyInput.trim();
    if (!cleanKey) return;

    setIsVerifying(true);
    setKeyError("");
    try {
      const res = await fetch("/api/license", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "activate", key: cleanKey }),
      });
      const data = await res.json();
      if (res.ok && data.valid) {
        try {
          localStorage.setItem("kavach_license_key", cleanKey);
          localStorage.setItem("kavach_license_tier", data.tier);
        } catch (_) {}
        setKeySuccess(true);
        setTier(data.tier);
        onTierChange?.(data.tier);
        setTimeout(() => setKeySuccess(false), 4000);
      } else {
        setKeyError(data.message || data.error || "Invalid cryptographic signature or expired key.");
      }
    } catch (err) {
      setKeyError("Verification service unavailable.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCopyCli = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText("kavach --login <KEY>");
      setCopiedCli(true);
      setTimeout(() => setCopiedCli(false), 2000);
    }
  };

  const navItems = [
    { id: "inspector" as ViewType, label: "Code Inspector", icon: Code2, badge: "AST Core" },
    { id: "posture" as ViewType, label: "Posture Dashboard", icon: Activity, badge: "Live" },
    { id: "benchmark" as ViewType, label: "Live Benchmark", icon: BarChart3, badge: "<16ms" },
    { id: "pricing" as ViewType, label: "Plans & Pricing", icon: CreditCard, badge: "Zero Tax" },
    { id: "github" as ViewType, label: "CI/CD & GitHub", icon: GitBranch, badge: "v1 Gate" },
  ];

  return (
    <aside className="w-[240px] border-r border-white/[0.08] bg-[#111114] flex flex-col justify-between shrink-0 h-screen select-none overflow-y-auto">
      <div>
        {/* Brand Header */}
        <div className="h-[52px] px-4 border-b border-white/[0.08] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="font-semibold text-xs text-[#FAFAFA] tracking-tight font-mono">
                Kavach AI
              </span>
              <span className="text-[9.5px] font-mono px-1.5 py-0.2 rounded bg-white/[0.06] text-zinc-400 border border-white/[0.08]">
                v1.5.0
              </span>
            </div>
          </div>
        </div>

        {/* Platform Navigation */}
        <div className="p-3">
          <div className="text-[10px] font-mono font-medium uppercase tracking-wider text-zinc-500 px-2 mb-1.5">
            Navigation
          </div>
          <nav className="space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`relative w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs transition-colors ${
                    isActive
                      ? "bg-white/[0.06] text-white font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:bg-emerald-500 before:rounded-r"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03]"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-3.5 h-3.5 ${isActive ? "text-emerald-400" : "text-zinc-500"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[9.5px] px-1.5 py-0.5 rounded font-mono ${
                      isActive 
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" 
                        : "bg-white/[0.04] text-zinc-500 border border-white/[0.04]"
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Account & Security Card */}
        <div className="px-3 pb-3">
          <div className="p-3 rounded-lg bg-[#09090B] border border-white/[0.08]">
            <div className="flex items-center justify-between pb-2 border-b border-white/[0.06] mb-2.5">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-zinc-300">
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span>License Key</span>
              </div>
              <span className="text-[9.5px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                {tier}
              </span>
            </div>

            {/* Widget Tabs */}
            <div className="flex items-center gap-1 p-0.5 rounded bg-[#111114] border border-white/[0.06] mb-2.5 text-[11px]">
              <button
                onClick={() => setAuthTab("pilot")}
                className={`flex-1 py-1 rounded text-center text-[10.5px] font-medium transition-colors ${
                  authTab === "pilot" ? "bg-white/[0.08] text-white font-semibold" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                Pilot
              </button>
              <button
                onClick={() => setAuthTab("key")}
                className={`flex-1 py-1 rounded text-center text-[10.5px] font-medium transition-colors ${
                  authTab === "key" ? "bg-white/[0.08] text-white font-semibold" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                Key
              </button>
              <button
                onClick={() => setAuthTab("signin")}
                className={`flex-1 py-1 rounded text-center text-[10.5px] font-medium transition-colors ${
                  authTab === "signin" ? "bg-white/[0.08] text-white font-semibold" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                Sign In
              </button>
            </div>

            {/* Tab Content */}
            {authTab === "pilot" && (
              <form onSubmit={handleClaimPilot} className="space-y-2">
                <p className="text-[10.5px] text-zinc-400 leading-relaxed">
                  Claim an instant 30-day VIP enterprise pilot pass:
                </p>
                <input
                  type="email"
                  required
                  value={pilotEmail}
                  onChange={(e) => setPilotEmail(e.target.value)}
                  placeholder="engineer@company.com"
                  className="w-full bg-[#111114] border border-white/[0.08] rounded px-2.5 py-1 text-xs text-white placeholder-zinc-500 outline-none focus:border-emerald-500/50 transition-colors"
                />
                <button
                  type="submit"
                  disabled={isVerifying}
                  className="w-full py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs shadow-sm transition-all active:scale-[0.98]"
                >
                  {isVerifying ? "Verifying..." : pilotSuccess ? "✓ 30-Day VIP Activated" : "Claim VIP Pilot"}
                </button>
              </form>
            )}

            {authTab === "key" && (
              <form onSubmit={handleActivateKey} className="space-y-2">
                <p className="text-[10.5px] text-zinc-400">Enter cryptographic license key:</p>
                <input
                  type="text"
                  required
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  placeholder="KAVACH-PRO-..."
                  className="w-full bg-[#111114] border border-white/[0.08] rounded px-2.5 py-1 text-xs text-white font-mono placeholder-zinc-500 outline-none focus:border-emerald-500/50 transition-colors"
                />
                {keyError && (
                  <p className="text-[10px] text-red-400 font-medium">{keyError}</p>
                )}
                <button
                  type="submit"
                  disabled={isVerifying}
                  className="w-full py-1.5 rounded bg-white/[0.06] hover:bg-white/[0.1] text-emerald-400 border border-emerald-500/20 font-semibold text-xs transition-colors"
                >
                  {isVerifying ? "Checking..." : keySuccess ? "✓ License Active" : "Activate License"}
                </button>
              </form>
            )}

            {authTab === "signin" && (
              <div className="space-y-2 text-[11px]">
                <p className="text-zinc-400 leading-relaxed">
                  Connect GitHub account for pre-merge PR inspection:
                </p>
                <button
                  type="button"
                  onClick={() => alert("GitHub OAuth Integration active via @rajrajak99/kavach-ai@v1")}
                  className="w-full py-1.5 rounded bg-white/[0.04] hover:bg-white/[0.08] text-zinc-200 border border-white/[0.08] font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
                >
                  <User className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Connect GitHub</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Telemetry Footer */}
      <div className="p-3 border-t border-white/[0.08] bg-[#09090B]/60 font-mono text-[11px] text-zinc-500 space-y-1.5">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]"></span>
          <span className="text-zinc-300 font-medium">100% Offline Engine</span>
        </div>
        <p className="text-[10px] text-zinc-500">Zero Code Retention • Air-Gapped</p>
        <div className="p-1.5 rounded bg-[#111114] border border-white/[0.08] text-zinc-400 flex items-center justify-between text-[10.5px]">
          <code>kavach --login &lt;KEY&gt;</code>
          <button 
            type="button" 
            onClick={handleCopyCli}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
            title="Copy command"
          >
            {copiedCli ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>
      </div>
    </aside>
  );
}
