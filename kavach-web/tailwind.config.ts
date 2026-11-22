import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: "#080A0E",
          900: "#0B0E14",
          850: "#0F131C",
          800: "#151A26",
          700: "#1E293B",
          600: "#334155",
        },
        slateText: {
          primary: "#F8FAFC",
          secondary: "#94A3B8",
          muted: "#64748B",
        },
        kavachEmerald: {
          DEFAULT: "#10B981",
          hover: "#059669",
          light: "#34D399",
          glow: "rgba(16, 185, 129, 0.25)",
        },
        kavachCyan: {
          DEFAULT: "#38BDF8",
          glow: "rgba(56, 189, 248, 0.20)",
        },
        kavachAmber: {
          DEFAULT: "#F59E0B",
          glow: "rgba(245, 158, 11, 0.15)",
        },
        kavachCrimson: {
          DEFAULT: "#EF4444",
          glow: "rgba(239, 68, 68, 0.15)",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
