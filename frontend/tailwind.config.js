/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: {
          deep: "var(--canvas-deep)",
        },
        surface: {
          pure: "var(--pure-surface)",
        },
        clinical: {
          white: "var(--clinical-white)",
        },
        muted: {
          steel: "var(--muted-steel)",
        },
        technical: {
          cyan: "var(--technical-cyan)",
        },
        forensic: {
          red: "var(--forensic-red)",
          amber: "var(--forensic-amber)",
          green: "var(--forensic-green)",
        },
        whisper: {
          border: "var(--whisper-border)",
        },
        background: "var(--canvas-deep)",
        foreground: "var(--clinical-white)",
        card: "var(--pure-surface)",
        border: "var(--whisper-border)",
        accent: "var(--technical-cyan)",
        danger: "var(--forensic-red)",
        warning: "var(--forensic-amber)",
        safe: "var(--forensic-green)",
        ring: "var(--technical-cyan)",
      },
      fontFamily: {
        sans: ['Geist', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        sm: '0.25rem',
        DEFAULT: '0.5rem',
        md: '0.75rem',
        lg: '1rem',
        xl: '1.5rem',
        full: '9999px',
      },
      boxShadow: {
        'whisper-drop': '0 4px 24px -4px rgba(0, 0, 0, 0.5), 0 0 1px 1px var(--whisper-border) inset',
      },
    },
  },
  plugins: [],
};
