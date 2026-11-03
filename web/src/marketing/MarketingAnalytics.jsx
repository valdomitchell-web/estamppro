import React, { useEffect, useState } from "react";

const STORAGE_KEY = "estamppro_analytics_consent_v1";
const MEASUREMENT_ID = import.meta.env.VITE_GA_MEASUREMENT_ID;

function getSavedChoice() {
  try {
    const choice = window.localStorage.getItem(STORAGE_KEY);
    return choice === "accepted" || choice === "declined" ? choice : null;
  } catch { return null; }
}

function startAnalytics() {
  if (!/^G-[A-Z0-9]+$/.test(MEASUREMENT_ID || "")) {
    console.warn("GA4 measurement ID is not configured.");
    return;
  }
  if (window.__estampGaStarted) return;
  window.__estampGaStarted = true;
  window.dataLayer = window.dataLayer || [];
  window.gtag = function gtag(){ window.dataLayer.push(arguments); };
  window.gtag("js", new Date());
  // Avoid sending full URLs containing campaign or other query parameters.
  window.gtag("config", MEASUREMENT_ID, {
    page_location: window.location.origin + window.location.pathname,
    send_page_view: true,
    allow_google_signals: false,
    allow_ad_personalization_signals: false,
  });
  const script = document.createElement("script");
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(MEASUREMENT_ID)}`;
  document.head.appendChild(script);
}

export default function MarketingAnalytics({ children }) {
  const [choice, setChoice] = useState(getSavedChoice);

  useEffect(() => {
    if (choice !== "accepted") return;
    startAnalytics();
    const handleClick = (event) => {
      const anchor = event.target.closest?.("a[href]");
      if (!anchor) return;
      let url;
      try { url = new URL(anchor.href); } catch { return; }
      if (url.hostname !== "app.estamppro.com" || url.searchParams.get("auth") !== "register") return;
      const location = anchor.closest("header") ? "header" :
        anchor.closest("section")?.querySelector("h1") ? "hero" :
        anchor.closest("section")?.querySelector("h2")?.textContent?.includes("Build trust into your next document") ? "footer" : "other";
      window.gtag?.("event", "start_free_click", { button_location: location });
    };
    document.addEventListener("click", handleClick, true);
    return () => document.removeEventListener("click", handleClick, true);
  }, [choice]);

  const choose = (value) => {
    try { window.localStorage.setItem(STORAGE_KEY, value); } catch { /* session-only choice */ }
    setChoice(value);
  };

  return <>
    {children}
    {choice === null && <div role="region" aria-label="Optional analytics cookies" style={{ position: "fixed", bottom: 16, left: 16, right: 16, maxWidth: 680, margin: "0 auto", zIndex: 9999, background: "#fff", border: "1px solid #bfdbfe", borderRadius: 14, boxShadow: "0 12px 38px rgba(15,23,42,.22)", padding: 18, color: "#0f172a", fontFamily: "inherit" }}>
      <strong>Help us improve eStamp Pro</strong>
      <p style={{ margin: "8px 0 14px", lineHeight: 1.5, fontSize: 14 }}>We use optional Google Analytics cookies to understand visits and which marketing channels bring people to our website. You can decline without affecting your access. Read our <a href="/privacy" style={{ color: "#1d4ed8" }}>Privacy Policy</a>.</p>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <button type="button" onClick={() => choose("accepted")} style={{ background: "#1d4ed8", color: "#fff", border: 0, borderRadius: 9, padding: "11px 16px", fontWeight: 700, cursor: "pointer" }}>Accept Analytics</button>
        <button type="button" onClick={() => choose("declined")} style={{ background: "#fff", color: "#1d4ed8", border: "1px solid #93c5fd", borderRadius: 9, padding: "11px 16px", fontWeight: 700, cursor: "pointer" }}>Decline</button>
      </div>
    </div>}
  </>;
}
