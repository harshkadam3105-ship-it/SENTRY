/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark background palette
        surface: {
          900: '#070b14',
          800: '#0d1117',
          700: '#111827',
          600: '#1a2234',
          500: '#1e293b',
        },
        // Severity
        severity: {
          critical: '#ef4444',
          'critical-bg': '#450a0a',
          high: '#f97316',
          'high-bg': '#431407',
          medium: '#eab308',
          'medium-bg': '#422006',
          low: '#94a3b8',
          'low-bg': '#1e293b',
        },
        // Accent
        cyber: {
          50:  '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
        },
        // MITRE tag
        mitre: {
          bg: '#1e1b4b',
          border: '#4338ca',
          text: '#a5b4fc',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'slide-in': 'slideIn 0.4s ease-out',
        'fade-in': 'fadeIn 0.3s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        slideIn: {
          '0%': { opacity: '0', transform: 'translateY(-8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(6,182,212,0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(6,182,212,0.7), 0 0 40px rgba(6,182,212,0.2)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
