import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import App from "./App.jsx";
import VerifyPage from "./VerifyPage.jsx";
import AdminDashboard from "./AdminDashboard.jsx";

import MarketingApp from "./marketing/MarketingApp.jsx";

const host = window.location.hostname;

const isMarketingSite =
  host === "estamppro.com" ||
  host === "www.estamppro.com";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    {isMarketingSite ? (
      <MarketingApp />
    ) : (
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<App />} />
          <Route path="/verify/:code" element={<VerifyPage />} />
          <Route path="/admin" element={<AdminDashboard />} />
        </Routes>
      </BrowserRouter>
    )}
  </React.StrictMode>
);