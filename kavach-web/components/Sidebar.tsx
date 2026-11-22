"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Code2, 
  Activity, 
  BarChart3, 
  CreditCard, 
  GitBranch, 
  Key, 
  Sparkles, 
  Lock, 
  User, 
  Check, 
  Copy,
  ExternalLink
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
      setKeyError("Please enter a valid enterprise corporate email.");
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

  const navItems = [
    { id: "inspector" as ViewType, label: "Code Inspector", icon: Code2, badge: "AST Core" },
    { id: "posture" as ViewType, label: "Posture Dashboard", icon: Activity, badge: "Live" },
    { id: "benchmark" as ViewType, label: "Live Benchmark", icon: BarChart3, badge: "<16ms" },
    { id: "pricing" as ViewType, label: "Plans & Pricing", icon: CreditCard, badge: "Zero Seat Tax" },
    { id: "github" as ViewType, label: "CI/CD & GitHub", icon: GitBranch, badge: "v1 Gate" },
  ];

  return (
    <aside className="w-64 border-r border-obsidian-700 bg-obsidian-900 flex flex-col justify-between shrink-0 h-screen select-none overflow-y-auto">
      <div>
        {/* Brand Header */}
        <div className="p-4 border-b border-obsidian-700/80 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-kavachEmerald/10 border border-kavachEmerald/30 flex items-center justify-center shadow-[0_0_12px_rgba(16,185,129,0.2)]">
            <Shield className="w-5 h-5 text-kavachEmerald fill-kavachEmerald/20" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm text-slateText-primary tracking-tight font-mono">
                Kavach AI
              </span>
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-kavachEmerald/15 text-kavachEmerald border border-kavachEmerald/30">
                v1.5.0
              </span>
            </div>
            <p className="text-[10.5px] text-slateText-muted">Deterministic AST Security</p>
          </div>
        </div>

        {/* Platform Navigation */}
        <div className="px-3 py-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slateText-muted px-2 mb-1.5">
            Platform Navigation
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-all ${
                    isActive
                      ? "bg-gradient-to-r from-kavachEmerald/15 to-obsidian-800 text-slateText-primary border-l-2 border-kavachEmerald shadow-[0_2px_10px_rgba(16,185,129,0.12)] font-semibold"
                      : "text-slateText-secondary hover:text-slateText-primary hover:bg-obsidian-850"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? "text-kavachEmerald" : "text-slateText-muted"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[9.5px] px-1.5 py-0.5 rounded font-mono ${
                      isActive 
                        ? "bg-kavachEmerald/20 text-kavachEmerald border border-kavachEmerald/30" 
                        : "bg-obsidian-800 text-slateText-muted"
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Account & Security Widget */}
        <div className="px-3 py-2 mx-3 mt-1 rounded-lg bg-obsidian-850 border border-obsidian-700/80">
          <div className="flex items-center justify-between pb-2 border-b border-obsidian-700/60 mb-2.5">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slateText-primary">
              <Lock className="w-3.5 h-3.5 text-kavachEmerald" />
              <span>Account & License</span>
            </div>
            <span className="text-[9.5px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-kavachEmerald border border-emerald-500/30 font-bold">
              {tier}
            </span>
          </div>

          {/* Widget Tabs */}
          <div className="flex items-center gap-1 p-0.5 rounded bg-obsidian-900 border border-obsidian-700/60 mb-2.5 text-[11px]">
            <button
              onClick={() => setAuthTab("pilot")}
              className={`flex-1 py-1 rounded text-center font-medium transition-colors ${
                authTab === "pilot" ? "bg-obsidian-800 text-kavachEmerald font-semibold" : "text-slateText-muted hover:text-slateText-secondary"
              }`}
            >
              ⚡ Pilot
            </button>
            <button
              onClick={() => setAuthTab("key")}
              className={`flex-1 py-1 rounded text-center font-medium transition-colors ${
                authTab === "key" ? "bg-obsidian-800 text-kavachEmerald font-semibold" : "text-slateText-muted hover:text-slateText-secondary"
              }`}
            >
              🔑 Key
            </button>
            <button
              onClick={() => setAuthTab("signin")}
              className={`flex-1 py-1 rounded text-center font-medium transition-colors ${
                authTab === "signin" ? "bg-obsidian-800 text-kavachEmerald font-semibold" : "text-slateText-muted hover:text-slateText-secondary"
              }`}
            >
              👤 Sign In
            </button>
          </div>

          {/* Tab Content */}
          {authTab === "pilot" && (
            <form onSubmit={handleClaimPilot} className="space-y-2">
              <p className="text-[10.5px] text-slateText-muted leading-relaxed">
                Claim an instant 30-day VIP enterprise pilot pass:
              </p>
              <input
                type="email"
                required
                value={pilotEmail}
                onChange={(e) => setPilotEmail(e.target.value)}
                placeholder="engineer@company.com"
                className="w-full bg-obsidian-900 border border-obsidian-700 rounded px-2.5 py-1 text-xs text-slateText-primary placeholder-slateText-muted outline-none focus:border-kavachEmerald"
              />
              <button
                type="submit"
                className="w-full py-1.5 rounded bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 font-bold text-xs shadow-[0_0_12px_rgba(16,185,129,0.3)] hover:opacity-95 transition-opacity"
              >
                {pilotSuccess ? "✓ 30-Day VIP Activated!" : "Claim 30-Day VIP Pilot"}
              </button>
            </form>
          )}

          {authTab === "key" && (
            <form onSubmit={handleActivateKey} className="space-y-2">
              <p className="text-[10.5px] text-slateText-muted">Enter license key to unlock features:</p>
              <input
                type="text"
                required
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder="KAVACH-PRO-..."
                className="w-full bg-obsidian-900 border border-obsidian-700 rounded px-2.5 py-1 text-xs text-slateText-primary font-mono placeholder-slateText-muted outline-none focus:border-kavachEmerald"
              />
              {keyError && (
                <p className="text-[10px] text-red-400 font-medium">{keyError}</p>
              )}
              <button
                type="submit"
                className="w-full py-1.5 rounded bg-obsidian-800 hover:bg-obsidian-700 text-kavachEmerald border border-kavachEmerald/40 font-semibold text-xs transition-colors"
              >
                {keySuccess ? "✓ License Active!" : "Activate License"}
              </button>
            </form>
          )}

          {authTab === "signin" && (
            <div className="space-y-2 text-[11px]">
              <p className="text-slateText-muted leading-relaxed">
                Connect your GitHub account for pre-merge PR inspection:
              </p>
              <button
                type="button"
                onClick={() => alert("GitHub OAuth Integration active via @rajrajak99/kavach-ai@v1")}
                className="w-full py-1.5 rounded bg-obsidian-800 hover:bg-obsidian-700 text-slateText-primary border border-obsidian-700 font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
              >
                <User className="w-3.5 h-3.5" />
                <span>Connect GitHub</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Telemetry Footer */}
      <div className="p-3.5 border-t border-obsidian-700/80 bg-obsidian-950/60 font-mono text-[10.5px] text-slateText-muted space-y-1.5">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-kavachEmerald animate-pulse"></span>
          <span className="text-slateText-secondary font-medium">100% Offline AST Engine</span>
        </div>
        <p className="text-[10px]">Zero Code Retention • Air-Gapped</p>
        <div className="p-1.5 rounded bg-obsidian-900 border border-obsidian-700 text-slateText-muted flex items-center justify-between">
          <code>kavach --login &lt;KEY&gt;</code>
          <Copy 
            className="w-3 h-3 hover:text-slateText-primary cursor-pointer" 
            onClick={() => navigator.clipboard.writeText("kavach --login <KEY>")}
          />
        </div>
      </div>
    </aside>
  );
}
