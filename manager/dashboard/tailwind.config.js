export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0a0e13',
          secondary: '#121820',
          tertiary: '#18202a',
          hover: '#202936',
        },
        border: {
          DEFAULT: '#2a3441',
          light: '#3a4654',
        },
        text: {
          primary: '#d8dee7',
          secondary: '#9aa4b2',
          muted: '#727d8b',
        },
        accent: {
          DEFAULT: '#7f8ea3',
          hover: '#a2adbd',
          glow: '#6f7f92',
        },
        protocol: {
          ssh: '#6f96ad',
          ftp: '#b18aa0',
          http: '#8fa88f',
          modbus: '#958bb0',
          mqtt: '#b59a75',
          telnet: '#ad8582',
        },
        verdict: {
          benign: '#7aa889',
          suspicious: '#c4a36a',
          malicious: '#c07d7d',
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
        'attack-flash': 'attackFlash 1.4s ease-out',
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
        attackFlash: {
          '0%':   { backgroundColor: 'rgba(192, 125, 125, 0.42)', borderColor: 'rgba(192, 125, 125, 0.78)', boxShadow: '0 0 12px 2px rgba(192, 125, 125, 0.36)', transform: 'scale(1.04)' },
          '40%':  { backgroundColor: 'rgba(192, 125, 125, 0.26)', borderColor: 'rgba(192, 125, 125, 0.52)', boxShadow: '0 0 8px 1px rgba(192, 125, 125, 0.24)', transform: 'scale(1.02)' },
          '100%': { backgroundColor: 'rgba(192, 125, 125, 0.0)',  borderColor: 'rgba(192, 125, 125, 0.0)',  boxShadow: '0 0 0 0 rgba(192, 125, 125, 0)',       transform: 'scale(1)' },
        },
      },
    },
  },
  plugins: [],
}

