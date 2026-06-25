import React from "react";
import PublicHeader from "./PublicHeader.jsx";
import PublicFooter from "./PublicFooter.jsx";
import HeroSection from "./HeroSection.jsx";

export default function HomePage() {
  return (
    <div style={{ minHeight: "100vh", background: "#ffffff", color: "#0f172a" }}>
      <PublicHeader />

      <HeroSection />

      <ConfidenceBar />

      <PublicFooter />
    </div>
  );
}

function ConfidenceBar() {
  const items = [
    "QR Verification",
    "Digital Certificates",
    "Audit Trail",
    "Team Collaboration",
    "API Integration",
    "Business Branding",
  ];

  return (
    <section style={{ background: "#0f172a", color: "#ffffff" }}>
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
          padding: "20px 24px",
          display: "flex",
          gap: 18,
          flexWrap: "wrap",
          justifyContent: "center",
          fontWeight: 800,
        }}
      >
        {items.map((item) => (
          <div key={item}>✓ {item}</div>
        ))}
      </div>
    </section>
  );
}