import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx"; // Imports your main application
import "./index.css"; // Imports the Tailwind CSS styles

// Finds the <div id="root"> in index.html and renders your App inside it
ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
