import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: 'class',
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#050a14',
          900: '#0a0f1e',
          800: '#0d1526',
          700: '#111c35',
          600: '#1e2d4a',
          500: '#2d4270',
        },
        'accent-blue': '#3b82f6',
        'accent-cyan': '#06b6d4',
        risk: {
          low: '#22c55e',
          suspicious: '#eab308',
          medium: '#f97316',
          high: '#f97316',
          critical: '#ef4444',
        },
      },
      backgroundImage: {
        'gradient-navy': 'linear-gradient(135deg, #0a0f1e 0%, #0d1526 100%)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
export default config
