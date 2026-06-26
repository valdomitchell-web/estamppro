import React from "react";

export default function PublicHeader() {
  const linkStyle = {
    color: "#334155",
    textDecoration: "none",
    fontWeight: 700,
  };

  const startFreeStyle = {
    background: "#1d4ed8",
    color: "#fff",
    textDecoration: "none",
    fontWeight: 800,
    padding: "10px 14px",
    borderRadius: 10,
  };

  return (
    <header style={{ background: "#fff", borderBottom: "1px solid #e2e8f0" }}>
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
          padding: "18px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 18,
          flexWrap: "wrap",
        }}
      >
        <a href="/" style={{ color: "#0f172a", textDecoration: "none" }}>
          <div style={{ fontSize: 24, fontWeight: 900 }}>eStamp Pro</div>
        </a>

        <nav style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
          <a href="/" style={linkStyle}>Home</a>
          <a href="/#features" style={linkStyle}>Features</a>
          <a href="/#pricing" style={linkStyle}>Pricing</a>
          <a href="/#trust" style={linkStyle}>About</a>
          <a href="/#footer" style={linkStyle}>Contact</a>
        </nav>

        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <a href="/?auth=login" style={linkStyle}>Login</a>
          <a href="/?auth=register" style={startFreeStyle}>
            Start Free
          </a>
        </div>
      </div>
    </header>
  );
}