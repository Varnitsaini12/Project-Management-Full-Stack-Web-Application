/** @type {import('tailwindcss').Config} */
export default {
    // --- ADD THIS LINE ---
    darkMode: 'class',

    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            fontFamily: {
                // This makes "Inter" the default font
                sans: ['Inter', 'sans-serif'],
            },
        },
    },
    plugins: [],
}

