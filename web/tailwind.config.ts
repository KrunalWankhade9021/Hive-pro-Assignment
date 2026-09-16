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
        // A briefing read late, under time pressure. The ground is slate-navy
        // rather than near-black: a document on a dimmed screen, not a console.
        ground: "#0F1620", // page
        surface: "#161F2B", // panel
        raised: "#1C2734", // panel on panel (feature block, hovered row)
        line: "#26313F", // hairline; used sparingly, depth carries structure
        ink: "#E8EDF3", // primary text, the brightest thing on the page
        muted: "#8B99AC", // secondary text
        faint: "#5E6C7D", // tertiary: units, provenance
        // One structural accent. Amber reads urgent but calm on slate, and
        // leaves red free to mean something specific.
        signal: "#D9822B",
        // Rationed: ransomware association and the top-ranked risk only. If
        // every row is an alarm, none of them is.
        alarm: "#E5534B",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        serif: ["var(--font-serif)", "Georgia", "serif"],
      },
      borderRadius: {
        DEFAULT: "3px",
        md: "4px",
        lg: "6px",
      },
    },
  },
  plugins: [],
};
export default config;
