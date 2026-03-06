/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'cyber-blue': '#00D4FF',
        'cyber-green': '#39FF14',
        'cyber-red': '#FF073A',
        'dark-bg': '#0A0A0A',
        'dark-card': '#1A1A1A',
      },
    },
  },
  plugins: [],
}
