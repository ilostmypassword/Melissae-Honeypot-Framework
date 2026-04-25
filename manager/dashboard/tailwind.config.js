export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0d1117',
          secondary: '#161b22',
          tertiary: '#1c2230',
          hover: '#21262d',
        },
        border: {
          DEFAULT: '#30363d',
          light: '#3d444d',
        },
        text: {
          primary: '#e6edf3',
          secondary: '#8b949e',
          muted: '#6e7681',
        },
        accent: {
          DEFAULT: '#6366f1',
          hover: '#818cf8',
          glow: '#6366f1',
        },
        protocol: {
          ssh: '#38bdf8',
          ftp: '#f9a8d4',
          http: '#86efac',
          modbus: '#a78bfa',
          mqtt: '#fdba74',
          telnet: '#fda4af',
        },
        verdict: {
          benign: '#4ade80',
          suspicious: '#fbbf24',
          malicious: '#f87171',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'card': '0 1px 2px rgba(0, 0, 0, 0.2)',
        'card-hover': '0 2px 8px rgba(0, 0, 0, 0.3)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
    },
  },
  plugins: [],
}

