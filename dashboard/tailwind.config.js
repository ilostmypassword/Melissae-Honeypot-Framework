/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0d1117',
          secondary: '#161b22',
          tertiary: '#1c2333',
          hover: '#242d3d',
        },
        border: {
          DEFAULT: '#30363d',
          light: '#3d444d',
        },
        text: {
          primary: '#e6edf3',
          secondary: '#8b949e',
          muted: '#656d76',
        },
        accent: {
          DEFAULT: '#6366f1',
          hover: '#818cf8',
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
    },
  },
  plugins: [],
}
