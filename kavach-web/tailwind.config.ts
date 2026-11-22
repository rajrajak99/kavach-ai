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
          950: "#09090B", // App background
          900: "#111114", // Elevated cards & sidebar
          850: "#18181D", // Hover & inputs
          800: "#222228", // Active states
          700: "rgba(255, 255, 255, 0.08)", // Hairline borders
          600: "rgba(255, 255, 255, 0.14)", // Hover borders
        },
        slateText: {
          primary: "#FAFAFA",
          secondary: "#A1A1AA",
          muted: "#71717A",
        },
        kavachEmerald: {
          DEFAULT: "#10B981",
          hover: "#059669",
          light: "#34D399",
          glow: "rgba(16, 185, 129, 0.20)",
        },
        kavachIndigo: {
          DEFAULT: "#6366F1",
          hover: "#4F46E5",
          light: "#818CF8",
          glow: "rgba(99, 102, 241, 0.20)",
        },
        kavachCyan: {
          DEFAULT: "#06B6D4",
          glow: "rgba(6, 182, 212, 0.20)",
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
        sans: ["var(--font-inter)", "Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["var(--font-mono)", "JetBrains Mono", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      borderColor: {
        hairline: "rgba(255, 255, 255, 0.08)",
        "hairline-hover": "rgba(255, 255, 255, 0.16)",
      },
    },
  },
  plugins: [],
};
export default config;
