/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "media",
  content: ["./internal/ui/templates/**/*.html", "./internal/ui/assets/**/*.css"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif"
        ]
      }
    }
  },
  plugins: []
};
