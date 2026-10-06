import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: { center: true, padding: "2rem" },
    extend: {
      colors: {
        border: "var(--border)",
        separator: "var(--separator)",
        input: "var(--input)",
        ring: "var(--ring)",
        focus: "var(--focus)",
        backdrop: "var(--backdrop)",
        overlay: { DEFAULT: "var(--overlay)", foreground: "var(--overlay-foreground)" },
        link: "var(--link)",
        chart: {
          c1: "var(--chart-c1)", c2: "var(--chart-c2)", c3: "var(--chart-c3)",
          c4: "var(--chart-c4)", c5: "var(--chart-c5)", c6: "var(--chart-c6)",
          c7: "var(--chart-c7)", c8: "var(--chart-c8)", c9: "var(--chart-c9)",
          netIn: "var(--chart-net-in)", netOut: "var(--chart-net-out)",
        },
        background: "var(--background)",
        foreground: "var(--foreground)",
        "background-secondary": "var(--background-secondary)",
        "background-tertiary": "var(--background-tertiary)",
        surface: {
          DEFAULT: "var(--surface)",
          foreground: "var(--surface-foreground)",
          hover: "var(--surface-hover)",
          secondary: "var(--surface-secondary)",
          tertiary: "var(--surface-tertiary)",
        },
        primary: {
          DEFAULT: "var(--primary)",
          foreground: "var(--primary-foreground)",
          soft: "var(--primary-soft)",
        },
        secondary: { DEFAULT: "var(--secondary)", foreground: "var(--secondary-foreground)" },
        muted: { DEFAULT: "var(--muted)", foreground: "var(--muted-foreground)" },
        faint: { DEFAULT: "var(--faint)", foreground: "var(--faint-foreground)" },
        accent: { DEFAULT: "var(--accent)", foreground: "var(--accent-foreground)" },
        destructive: {
          DEFAULT: "var(--destructive)",
          foreground: "var(--destructive-foreground)",
          soft: "var(--destructive-soft)",
        },
        success: {
          DEFAULT: "var(--success)",
          foreground: "var(--success-foreground)",
          soft: "var(--success-soft)",
        },
        warning: {
          DEFAULT: "var(--warning)",
          foreground: "var(--warning-foreground)",
          soft: "var(--warning-soft)",
        },
        info: {
          DEFAULT: "var(--info)",
          foreground: "var(--info-foreground)",
          soft: "var(--info-soft)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        xl: "calc(var(--radius) + 4px)",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(16 18 24 / 0.04), 0 1px 1px -1px rgb(16 18 24 / 0.03)",
        pop: "0 4px 12px -2px rgb(16 18 24 / 0.08), 0 2px 4px -2px rgb(16 18 24 / 0.05)",
      },
    },
  },
} satisfies Config;
