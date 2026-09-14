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
        // Neutral base, an analyst dossier, not a SaaS dashboard.
        paper: "#F4F5F7", // cool off-white page background
        card: "#FFFFFF", // card surface
        ink: "#191C22", // primary text (near-black)
        muted: "#5B616E", // secondary text (grey)
        line: "#E3E5E9", // hairline borders
        // The single structural accent.
        navy: "#1B3A5B",
        // Severity, the only place bright colour appears.
        sev: {
          critical: "#B42318",
          high: "#B54708",
          medium: "#475467",
          low: "#5B616E",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        serif: ["var(--font-serif)", "Georgia", "serif"],
      },
      borderRadius: {
        // Restrained corners, no big pill cards.
        DEFAULT: "3px",
        md: "4px",
        lg: "5px",
      },
    },
  },
  plugins: [],
};
export default config;
