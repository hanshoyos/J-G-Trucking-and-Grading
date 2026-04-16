import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'ace-bg': '#020617',
        'ace-card': '#0f172a',
        'ace-border': '#1e293b',
      }
    },
  },
  plugins: [],
}
export default config
