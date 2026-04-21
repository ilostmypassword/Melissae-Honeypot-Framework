export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0a0e14',
          secondary: '#111820',
          tertiary: '#171f2b',
          hover: '#1e2a3a',
        },
        border: {
          DEFAULT: '#1e2d3d',
          light: '#2a3f52',
        },
        text: {
          primary: '#e6edf3',
          secondary: '#8b949e',
          muted: '#5a6370',
        },
        accent: {
          DEFAULT: '#7c3aed',
          hover: '#a78bfa',
          glow: '#7c3aed',
        },
        protocol: {
          ssh: '#22d3ee',
          ftp: '#f472b6',
          http: '#a3e635',
          modbus: '#c084fc',
          mqtt: '#fb923c',
          telnet: '#f43f5e',
        },
        verdict: {
          benign: '#22c55e',
          suspicious: '#f59e0b',
          malicious: '#ef4444',
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

