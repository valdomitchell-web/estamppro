import React from "react";

export default function PublicFooter() {
  const linkStyle = {
    color: "#cbd5e1",
    textDecoration: "none",
    display: "block",
    marginBottom: 8,
  };

  return (
    <footer id="footer" style={{ background: "#0f172a", color: "#e2e8f0", marginTop: 60 }}>
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
          padding: "42px 24px",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 28,
        }}
      >
        <div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff" }}>
            eStamp Pro
          </div>
          <p style={{ color: "#cbd5e1", lineHeight: 1.6 }}>
            Secure electronic document stamping, verification, certificates,
            and audit trails for modern businesses.
          </p>
        </div>

        <div>
          <h3 style={{ color: "#fff" }}>Product</h3>
          <a href="/#features" style={linkStyle}>Features</a>
          <a href="/#pricing" style={linkStyle}>Pricing</a>
          <a href="/#about" style={linkStyle}>About</a>
          <a href="/#contact" style={linkStyle}>Contact</a>
        </div>

        <div>
          <h3 style={{ color: "#fff" }}>Legal</h3>
          <a href="/privacy" style={linkStyle}>Privacy Policy</a>
          <a href="/terms" style={linkStyle}>Terms of Service</a>
          <a href="/refunds" style={linkStyle}>Refund Policy</a>
        </div>

        <div>
          <h3 style={{ color: "#fff" }}>Support</h3>
          <p style={{ color: "#cbd5e1", lineHeight: 1.6 }}>
            support@estamppro.com
            <br />
            Grenada
            <br />
            Response time: 1–2 business days
          </p>
        </div>
      </div>

      <div
        style={{
          borderTop: "1px solid #1e293b",
          padding: "18px 24px",
          textAlign: "center",
          color: "#94a3b8",
        }}
      >
        © 2026 eStamp Pro. All rights reserved.
      </div>
    </footer>
  );
}