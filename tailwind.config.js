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
          50:  '#fbf6ef',
          100: '#f4e8d4',
          200: '#e8d2a9',
          300: '#d6b475',
          400: '#c2914a',
          500: '#a87035',
          600: '#8a5728',
          700: '#6e4220',
          800: '#58351c',
          900: '#422813',
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
