/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
        "./node_modules/@shadcn/ui/dist/**/*.js",
        "./src/**/*.{ts,tsx,js,jsx}"
    ],
    theme: {
        extend: {},
    },
    plugins: [],
};
