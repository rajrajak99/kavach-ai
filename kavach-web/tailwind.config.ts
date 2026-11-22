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
          950: "#090B0F",
          900: "#0D1015",
          850: "#11151B",
          800: "#171C24",
          700: "#252B35",
          600: "#363E4D",
        },
        slateText: {
          primary: "#F1F3F5",
          secondary: "#929BA8",
          muted: "#667080",
        },
        kavachEmerald: {
          DEFAULT: "#22C58B",
          glow: "rgba(34, 197, 139, 0.15)",
        },
        kavachAmber: {
          DEFAULT: "#E9A23B",
          glow: "rgba(233, 162, 59, 0.15)",
        },
        kavachCrimson: {
          DEFAULT: "#F05252",
          glow: "rgba(240, 82, 82, 0.15)",
        },
        kavachGold: {
          DEFAULT: "#C9A96E",
          hover: "#D9B77B",
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
