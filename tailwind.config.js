/** @type {import('tailwindcss').Config} */
module.exports = {
  // Tailwind scans these files for class names. The app is one HTML file
  // and one markdown guide, so we point at both. Add new files here if
  // the app ever splits.
  content: [
    './index.html',
    './HR_USER_GUIDE.md',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans:    ['Inter', 'Cairo', 'system-ui', 'sans-serif'],
        display: ['Fraunces', 'Cairo', 'Georgia', 'serif'],
      },
      colors: {
        brand: {
          50:  '#fff1f2',
          100: '#ffe4e6',
          200: '#fecdd3',
          300: '#fda4af',
          400: '#fb7185',
          500: '#df3247',
          600: '#c81e3a',
          700: '#a8172e',
          800: '#881228',
          900: '#6b0f20',
        },
        accent: {
          500: '#c44a4a',
          600: '#a93838',
          700: '#8c2929',
        },
      },
      boxShadow: {
        card: '0 1px 2px rgba(15,23,42,0.04), 0 1px 3px rgba(15,23,42,0.06)',
        pop:  '0 10px 30px rgba(15,23,42,0.12), 0 2px 6px rgba(15,23,42,0.06)',
      },
    },
  },
  plugins: [],
};
