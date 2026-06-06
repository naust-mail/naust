import type { Config } from 'tailwindcss'

export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{vue,ts}',
  ],
  theme: {
    extend: {
      colors: {
        // Open WebUI custom gray token - used extensively for dark-mode surfaces
        gray: { 850: 'oklch(0.27 0 0)' },
      },
      borderRadius: {
        '4xl': '2rem',
      },
      boxShadow: {
        // Extends Tailwind's shadow-2xl for deep modal/panel shadows
        '3xl': '0 35px 60px -15px rgb(0 0 0 / 0.3)',
      },
      transitionProperty: {
        width: 'width',
      },
      transitionDuration: {
        fast: '150ms',
        base: '200ms',
        slow: '250ms',
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Inter', 'ui-sans-serif', 'system-ui'],
      },
    },
  },
  plugins: [],
} satisfies Config
