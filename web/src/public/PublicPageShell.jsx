import React from "react";
import PublicHeader from "./PublicHeader.jsx";
import PublicFooter from "./PublicFooter.jsx";

export default function PublicPageShell({ title, subtitle, children }) {
  return (
    <div style={{ minHeight: "100vh", background: "#f8fafc", color: "#0f172a" }}>
      <PublicHeader />

      <main style={{ maxWidth: 1120, margin: "0 auto", padding: "48px 24px" }}>
        <section
          style={{
            background: "#ffffff",
            border: "1px solid #dbe4f0",
            borderRadius: 20,
            padding: 34,
            boxShadow: "0 10px 30px rgba(15,23,42,0.06)",
            lineHeight: 1.7,
          }}
        >
          <h1 style={{ marginTop: 0, fontSize: 40 }}>{title}</h1>
          {subtitle ? <p style={{ color: "#475569", fontSize: 18 }}>{subtitle}</p> : null}
          {children}
        </section>
      </main>

      <PublicFooter />
    </div>
  );
}