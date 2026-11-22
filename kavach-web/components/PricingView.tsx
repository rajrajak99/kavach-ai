"use client";

import React, { useState } from "react";
import { Check, Shield, Zap, Sparkles } from "lucide-react";

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
    },
    {
      name: "Growth Team",
      price: isAnnual ? "$990" : "$99",
      period: isAnnual ? "/year" : "/month",
      sub: isAnnual ? "$990 billed annually (Save $198) • Teams" : "$99 billed monthly • High-speed startups",
      badge: "Most Popular For Startups",
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
        "24/7 Priority SLA & dedicated lead",
      ],
      buttonText: "Contact Enterprise",
      featured: false,
    },
  ];

  return (
    <div className="flex-1 p-6 lg:p-8 overflow-y-auto space-y-8 max-w-6xl mx-auto">
      {/* Title & Billing Toggle */}
      <div className="text-center max-w-2xl mx-auto space-y-3">
        <h2 className="text-2xl font-bold tracking-tight text-white font-sans">
          Zero Per-Seat Developer Tax. Predictable Enterprise Pricing.
        </h2>
        <p className="text-xs text-zinc-400 leading-relaxed">
          Legacy security vendors charge $50–$95/seat/month. Kavach AI delivers flat-rate, sub-16ms AST security gates that scale with your code, not your headcount.
        </p>

        {/* Toggle */}
        <div className="inline-flex items-center gap-1 p-1 rounded-full bg-white/[0.04] border border-white/[0.08] mt-3">
          <button
            onClick={() => setIsAnnual(false)}
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition-all ${
              !isAnnual ? "bg-white/[0.08] text-white shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Monthly Billing
          </button>
          <button
            onClick={() => setIsAnnual(true)}
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition-all flex items-center gap-1.5 ${
              isAnnual ? "bg-white/[0.08] text-white shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <span>Annual (2 Months Free)</span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
              Save $198+
            </span>
          </button>
        </div>
      </div>

      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {plans.map((p, idx) => (
          <div
            key={idx}
            className={`rounded-xl p-5 flex flex-col justify-between relative transition-all card-top-shine ${
              p.featured
                ? "bg-[#111114] border border-emerald-500/40 shadow-[0_0_24px_rgba(16,185,129,0.1)]"
                : "bg-[#111114] border border-white/[0.08] hover:border-white/[0.14]"
            }`}
          >
            {p.badge && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-semibold whitespace-nowrap">
                {p.badge}
              </div>
            )}

            <div>
              <div className="text-xs font-semibold text-white mb-1">{p.name}</div>
              <div className="flex items-baseline gap-1 my-3">
                <span className="text-2xl font-bold font-mono tabular-nums text-white">{p.price}</span>
                {p.period && <span className="text-xs text-zinc-500 font-mono">{p.period}</span>}
              </div>
              <p className="text-[11px] text-zinc-400 min-h-[32px] leading-relaxed mb-4">{p.sub}</p>

              <div className="space-y-2 border-t border-white/[0.06] pt-4 mb-6">
                {p.features.map((f, fi) => (
                  <div key={fi} className="flex items-start gap-2 text-xs text-zinc-300">
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span className="leading-tight text-[11.5px]">{f}</span>
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
              className={`w-full py-2 rounded-lg text-xs font-semibold transition-all active:scale-[0.98] ${
                p.featured
                  ? "bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-sm"
                  : "bg-white/[0.04] hover:bg-white/[0.08] text-zinc-200 border border-white/[0.08]"
              }`}
            >
              {p.buttonText}
            </button>
          </div>
        ))}
      </div>

      {/* ROI Table */}
      <div className="rounded-xl bg-[#111114] border border-white/[0.08] overflow-hidden card-top-shine">
        <div className="p-4 bg-white/[0.02] border-b border-white/[0.08] flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-white">
            Transparent ROI: Kavach AI vs Legacy Security Scanners
          </span>
          <span className="text-[11px] font-mono font-medium text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded border border-emerald-500/20">
            Save $3,810+ Every Single Year
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-white/[0.08] text-zinc-500 uppercase tracking-wider text-[10.5px] font-mono bg-white/[0.01]">
                <th className="py-3 px-4 font-medium">Feature / Metric</th>
                <th className="py-3 px-4 bg-emerald-500/[0.06] text-emerald-400 border-x border-emerald-500/20 font-semibold">
                  Kavach AI (Growth Team)
                </th>
                <th className="py-3 px-4 font-medium">Semgrep Team</th>
                <th className="py-3 px-4 font-medium">Snyk Developer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04] text-zinc-300">
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">Monthly Cost</td>
                <td className="py-3 px-4 bg-emerald-500/[0.03] text-emerald-400 border-x border-emerald-500/20 font-semibold font-mono tabular-nums">$99 / month</td>
                <td className="py-3 px-4 font-mono tabular-nums text-zinc-400">$400 / month</td>
                <td className="py-3 px-4 font-mono tabular-nums text-zinc-400">$500 / month</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">Annual Subscription</td>
                <td className="py-3 px-4 bg-emerald-500/[0.03] text-emerald-400 border-x border-emerald-500/20 font-semibold font-mono tabular-nums">$990 / year</td>
                <td className="py-3 px-4 font-mono tabular-nums text-zinc-400">$4,800 / year</td>
                <td className="py-3 px-4 font-mono tabular-nums text-zinc-400">$6,000 / year</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">Per-Seat Developer Tax</td>
                <td className="py-3 px-4 bg-emerald-500/[0.03] text-emerald-400 border-x border-emerald-500/20 font-semibold font-mono tabular-nums">$0 (Zero Per-Seat Fee)</td>
                <td className="py-3 px-4 text-zinc-400 font-mono">$40 to $65 / seat / mo</td>
                <td className="py-3 px-4 text-zinc-400 font-mono">$50 to $95 / seat / mo</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">CI/CD Scan Latency</td>
                <td className="py-3 px-4 bg-emerald-500/[0.03] text-emerald-400 border-x border-emerald-500/20 font-semibold font-mono tabular-nums">&lt; 16ms (Instant AST)</td>
                <td className="py-3 px-4 text-zinc-400 font-mono">2 to 8 seconds</td>
                <td className="py-3 px-4 text-zinc-400 font-mono">15 to 45 seconds</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">1-Click Auto-Remediation</td>
                <td className="py-3 px-4 bg-emerald-500/[0.03] text-emerald-400 border-x border-emerald-500/20 font-semibold font-mono">Included (Direct Diffs)</td>
                <td className="py-3 px-4 text-zinc-400">Manual developer edits</td>
                <td className="py-3 px-4 text-zinc-400">Frequent breakages</td>
              </tr>
              <tr className="bg-emerald-500/10 font-bold">
                <td className="py-3.5 px-4 text-white">Annual Team Cost</td>
                <td className="py-3.5 px-4 text-emerald-400 border-x border-emerald-500/30 font-mono text-sm tabular-nums">$990 / year</td>
                <td className="py-3.5 px-4 text-red-400 font-mono text-sm tabular-nums">$4,800 / year</td>
                <td className="py-3.5 px-4 text-red-400 font-mono text-sm tabular-nums">$6,000 / year</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
