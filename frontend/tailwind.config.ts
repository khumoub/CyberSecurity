import type { Config } from 'tailwindcss';
const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: '#0a0b0d', card: '#111318', sidebar: '#0d0f14', border: '#1e2028' },
        accent: { cyan: '#00d4ff', green: '#00ff88', orange: '#ff6b35', red: '#ff3b3b', yellow: '#ffcc00', blue: '#4fc3f7' },
        severity: { critical: '#ff3b3b', high: '#ff6b35', medium: '#ffcc00', low: '#4fc3f7', info: '#8892a4' }
      },
      fontFamily: { mono: ['ui-monospace', 'SFMono-Regular', 'monospace'] }
    }
  },
  plugins: []
};
export default config;
