/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Light beige color palette
        beige: {
          50: '#fefdfb',
          100: '#fdf9f3',
          200: '#faf2e4',
          300: '#f5e6d0',
          400: '#eed5b7',
          500: '#e4c29f',
          600: '#d4a574',
          700: '#c4915c',
          800: '#a3784d',
          900: '#856142',
          950: '#463221',
        },
        cream: {
          50: '#fefefe',
          100: '#fefcf9',
          200: '#fdf8f1',
          300: '#fbf2e6',
          400: '#f7e8d4',
          500: '#f1dcc0',
          600: '#e8c89f',
          700: '#ddb07a',
          800: '#cd9660',
          900: '#a67c4f',
          950: '#5a4229',
        },
        sand: {
          50: '#fefefe',
          100: '#fefcfa',
          200: '#fdf7f0',
          300: '#fbf0e4',
          400: '#f7e4d1',
          500: '#f1d5b8',
          600: '#e7c094',
          700: '#daa66e',
          800: '#c8904f',
          900: '#a17543',
          950: '#563e23',
        },
        // Accent colors for buttons and highlights
        amber: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
          950: '#451a03',
        },
        bronze: {
          50: '#fdf8f3',
          100: '#faeee1',
          200: '#f4dcc2',
          300: '#ecc498',
          400: '#e2a66c',
          500: '#da8f4a',
          600: '#cc7a3f',
          700: '#aa6536',
          800: '#885232',
          900: '#6e442b',
          950: '#3b2316',
        }
      },
      animation: {
        'float': 'float 6s ease-in-out infinite',
        'float-delayed': 'float 6s ease-in-out infinite 2s',
        'rotate-slow': 'rotate 20s linear infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite alternate',
        'slide-up': 'slide-up 0.5s ease-out',
        'slide-down': 'slide-down 0.5s ease-out',
        'bounce-3d': 'bounce-3d 1s ease-in-out infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px) rotate(0deg)' },
          '50%': { transform: 'translateY(-20px) rotate(5deg)' },
        },
        'pulse-glow': {
          '0%': { boxShadow: '0 0 20px rgba(218, 143, 74, 0.5)' },
          '100%': { boxShadow: '0 0 40px rgba(218, 143, 74, 0.8)' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'bounce-3d': {
          '0%, 20%, 53%, 80%, 100%': { transform: 'translate3d(0,0,0) rotateX(0deg)' },
          '40%, 43%': { transform: 'translate3d(0,-30px,0) rotateX(-10deg)' },
          '70%': { transform: 'translate3d(0,-15px,0) rotateX(-5deg)' },
          '90%': { transform: 'translate3d(0,-4px,0) rotateX(-2deg)' },
        },
        'shimmer': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      perspective: {
        '1000': '1000px',
        '2000': '2000px',
      },
      transformStyle: {
        'preserve-3d': 'preserve-3d',
      },
      boxShadow: {
        '3d': '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04), inset 0 1px 0 rgba(255, 255, 255, 0.1)',
        '3d-hover': '0 20px 40px -10px rgba(0, 0, 0, 0.15), 0 10px 20px -5px rgba(0, 0, 0, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
        'inner-3d': 'inset 0 2px 4px rgba(0, 0, 0, 0.1), inset 0 -2px 4px rgba(255, 255, 255, 0.1)',
      }
    },
  },
  plugins: [],
};