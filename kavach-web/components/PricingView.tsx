"use client";

import React, { useState } from "react";
import { Check, Shield, Zap, Sparkles, Building2, Terminal } from "lucide-react";

export default function PricingView() {
  const [isAnnual, setIsAnnual] = useState(true);

  const plans = [
    {
      name: "Free Community",
      price: "$0",
      sub: "Free forever for public open-source repos",
      features: [
        "100% Offline AST scanner",
        "Sub-16ms latency gate",
        "Public GitHub repositories",
        "CLI local integration",
        "Community support",
      ],
      buttonText: "Current Plan",
      featured: false,
      buttonVariant: "secondary",
    },
    {
      name: "Developer Pro",
      price: isAnnual ? "$10" : "$1",
      period: isAnnual ? "/year" : "/month",
      sub: isAnnual ? "$10 billed annually • Single engineers" : "$1 billed monthly • Personal projects",
      features: [
        "Unlimited private repos (1 seat)",
        "Automated PR review bot",
        "1-Click surgical code healing",
        "VS Code lightbulb quick-fixes",
        "Standard CI/CD execution queue",
      ],
      buttonText: "Upgrade Developer Pro",
      featured: false,
      buttonVariant: "secondary",
    },
    {
      name: "Growth Team",
      price: isAnnual ? "$990" : "$99",
      period: isAnnual ? "/year" : "/month",
      sub: isAnnual ? "$990 billed annually (Save $198) • Teams" : "$99 billed monthly • High-speed startups",
      badge: "🔥 Most Popular For Startups",
      features: [
        "Up to 15 engineers (Zero per-seat tax)",
        "Unlimited private repositories",
        "Automated PR merge blocker gate",
        "SOC 2 / ISO-27001 Pre-Audit Generator",
        "Pytest self-healing test engine",
        "Priority CI queue & SLA response",
      ],
      buttonText: "Upgrade Growth Team",
      featured: true,
      buttonVariant: "primary",
    },
    {
      name: "Global Enterprise",
      price: isAnnual ? "$4,990" : "$499",
      period: isAnnual ? "/year" : "/month",
      sub: isAnnual ? "$4,990 billed annually (Save $998)" : "$499 billed monthly • Large organizations",
      features: [
        "Unlimited engineers & orgs",
        "100% air-gapped Docker runner",
        "Custom AST rules & proprietary patterns",
        "Signed executive compliance audits",
        "SOC 2, HIPAA, PCI-DSS exports",
        "24/7 Priority SLA & dedicated security lead",
      ],
      buttonText: "Contact Enterprise",
      featured: false,
      buttonVariant: "secondary",
    },
  ];

  return (
    <div className="flex-1 p-6 lg:p-8 overflow-y-auto space-y-8 max-w-6xl mx-auto">
      {/* Title & Billing Toggle */}
      <div className="text-center max-w-2xl mx-auto space-y-3">
        <h2 className="text-2xl lg:text-3xl font-bold tracking-tight text-slateText-primary bg-gradient-to-b from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
          Zero Per-Seat Developer Tax. Predictable Enterprise Pricing.
        </h2>
        <p className="text-xs sm:text-sm text-slateText-secondary">
          Legacy security vendors charge $50–$95/seat/month. Kavach AI delivers flat-rate, sub-16ms AST security gates that scale with your code, not your headcount.
        </p>

        {/* Toggle */}
        <div className="inline-flex items-center gap-3 p-1 rounded-full bg-obsidian-850 border border-obsidian-700 mt-2">
          <button
            onClick={() => setIsAnnual(false)}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
              !isAnnual ? "bg-obsidian-800 text-slateText-primary shadow-sm" : "text-slateText-muted hover:text-slateText-secondary"
            }`}
          >
            Monthly Billing
          </button>
          <button
            onClick={() => setIsAnnual(true)}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all flex items-center gap-1.5 ${
              isAnnual ? "bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 font-bold shadow-[0_0_12px_rgba(16,185,129,0.3)]" : "text-slateText-muted hover:text-slateText-secondary"
            }`}
          >
            <span>Annual (2 Months Free)</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-obsidian-950/40 text-emerald-200">Save $198+</span>
          </button>
        </div>
      </div>

      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {plans.map((p, idx) => (
          <div
            key={idx}
            className={`rounded-xl p-5 flex flex-col justify-between relative transition-all ${
              p.featured
                ? "bg-obsidian-850 border-2 border-kavachEmerald shadow-[0_4px_30px_rgba(16,185,129,0.18)]"
                : "bg-obsidian-900 border border-obsidian-700/80 hover:border-obsidian-600"
            }`}
          >
            {p.badge && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 text-[10px] font-bold shadow-[0_2px_8px_rgba(16,185,129,0.4)] whitespace-nowrap">
                {p.badge}
              </div>
            )}

            <div>
              <div className="text-sm font-bold text-slateText-primary mb-1">{p.name}</div>
              <div className="flex items-baseline gap-1 my-3">
                <span className="text-3xl font-extrabold font-mono text-slateText-primary">{p.price}</span>
                {p.period && <span className="text-xs text-slateText-muted font-medium">{p.period}</span>}
              </div>
              <p className="text-[11px] text-slateText-muted min-h-[32px] leading-relaxed mb-4">{p.sub}</p>

              <div className="space-y-2 border-t border-obsidian-700/60 pt-4 mb-6">
                {p.features.map((f, fi) => (
                  <div key={fi} className="flex items-start gap-2 text-xs text-slateText-secondary">
                    <Check className="w-3.5 h-3.5 text-kavachEmerald shrink-0 mt-0.5" />
                    <span className="leading-tight">{f}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={() => {
                if (p.name.includes("Free")) {
                  alert("You are on the Free Community tier.");
                } else if (p.name.includes("Enterprise")) {
                  window.open("mailto:team.kavachai@gmail.com?subject=Enterprise%20Plan%20Inquiry", "_blank", "noopener,noreferrer");
                } else {
                  window.open("https://github.com/rajrajak99/kavach-ai#pricing", "_blank", "noopener,noreferrer");
                }
              }}
              className={`w-full py-2 rounded-lg text-xs font-bold transition-all ${
                p.featured
                  ? "bg-gradient-to-r from-kavachEmerald to-emerald-600 text-obsidian-950 shadow-[0_0_15px_rgba(16,185,129,0.35)] hover:opacity-95"
                  : "bg-obsidian-800 hover:bg-obsidian-750 text-slateText-primary border border-obsidian-700"
              }`}
            >
              {p.buttonText}
            </button>
          </div>
        ))}
      </div>

      {/* ROI Table */}
      <div className="rounded-xl bg-obsidian-850 border border-obsidian-700 overflow-hidden shadow-sm">
        <div className="p-4 bg-obsidian-800 border-b border-obsidian-700 flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-slateText-primary">
            💰 Transparent ROI: Kavach AI vs Legacy Security Scanners
          </span>
          <span className="text-xs font-mono font-bold text-kavachEmerald bg-kavachEmerald/15 px-2.5 py-0.5 rounded border border-kavachEmerald/30">
            Save $3,810+ Every Single Year
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-obsidian-900 border-b border-obsidian-700 text-slateText-muted uppercase tracking-wider text-[10.5px]">
                <th className="py-3 px-4">Feature / Metric</th>
                <th className="py-3 px-4 bg-kavachEmerald/10 text-kavachEmerald border-x border-kavachEmerald/20 font-bold">
                  🛡️ Kavach AI (Growth Team)
                </th>
                <th className="py-3 px-4">Semgrep Team</th>
                <th className="py-3 px-4">Snyk Developer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-obsidian-700/60 text-slateText-secondary">
              <tr className="hover:bg-obsidian-800/30">
                <td className="py-3 px-4 font-semibold text-slateText-primary">Monthly Cost</td>
                <td className="py-3 px-4 bg-kavachEmerald/5 text-kavachEmerald border-x border-kavachEmerald/20 font-bold font-mono">$99 / month</td>
                <td className="py-3 px-4">$400 / month</td>
                <td className="py-3 px-4">$500 / month</td>
              </tr>
              <tr className="hover:bg-obsidian-800/30">
                <td className="py-3 px-4 font-semibold text-slateText-primary">Annual Subscription</td>
                <td className="py-3 px-4 bg-kavachEmerald/5 text-kavachEmerald border-x border-kavachEmerald/20 font-bold font-mono">$990 / year</td>
                <td className="py-3 px-4">$4,800 / year</td>
                <td className="py-3 px-4">$6,000 / year</td>
              </tr>
              <tr className="hover:bg-obsidian-800/30">
                <td className="py-3 px-4 font-semibold text-slateText-primary">Per-Seat Developer Tax</td>
                <td className="py-3 px-4 bg-kavachEmerald/5 text-kavachEmerald border-x border-kavachEmerald/20 font-bold font-mono">$0 (Zero Per-Seat Fee)</td>
                <td className="py-3 px-4">$40 to $65 / seat / mo</td>
                <td className="py-3 px-4">$50 to $95 / seat / mo</td>
              </tr>
              <tr className="hover:bg-obsidian-800/30">
                <td className="py-3 px-4 font-semibold text-slateText-primary">CI/CD Scan Latency</td>
                <td className="py-3 px-4 bg-kavachEmerald/5 text-kavachEmerald border-x border-kavachEmerald/20 font-bold font-mono">&lt; 16ms (Instant AST)</td>
                <td className="py-3 px-4">2 to 8 seconds</td>
                <td className="py-3 px-4">15 to 45 seconds</td>
              </tr>
              <tr className="hover:bg-obsidian-800/30">
                <td className="py-3 px-4 font-semibold text-slateText-primary">1-Click Auto-Remediation</td>
                <td className="py-3 px-4 bg-kavachEmerald/5 text-kavachEmerald border-x border-kavachEmerald/20 font-bold font-mono">Included (Direct Diffs)</td>
                <td className="py-3 px-4">Manual developer edits</td>
                <td className="py-3 px-4">Frequent breakages</td>
              </tr>
              <tr className="bg-kavachEmerald/10 font-bold">
                <td className="py-3.5 px-4 text-slateText-primary">Annual Team Cost</td>
                <td className="py-3.5 px-4 text-kavachEmerald border-x border-kavachEmerald/30 font-mono text-sm">$990 / year</td>
                <td className="py-3.5 px-4 text-red-400 font-mono">$4,800 / year</td>
                <td className="py-3.5 px-4 text-red-400 font-mono">$6,000 / year</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
