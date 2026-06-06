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
        // Pure neutral gray scale - no blue cast.
        // Tailwind v3 default grays carry chroma at hue 264, making dark
        // surfaces appear blue-tinted. These hex values are exact conversions
        // of the equivalent achromatic OKLCH values (C=0).
        gray: {
          50:  '#f8f8f8',
          100: '#ebebeb',
          200: '#e4e4e4',
          300: '#cecece',
          400: '#b4b4b4',
          500: '#9b9b9b',
          600: '#666666',
          700: '#4d4d4d',
          800: '#333333',
          850: '#262626',
          900: '#161616',
          950: '#0d0d0d',
        },
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
