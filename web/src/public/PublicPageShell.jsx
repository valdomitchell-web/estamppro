import React from "react";

export default function PublicPageShell({ title, subtitle, children }) {
  return (
    <div style={{ minHeight: "100vh", background: "#f8fafc", color: "#0f172a" }}>
      <header
        style={{
          background: "#1d4ed8",
          color: "#fff",
          padding: "22px 28px",
        }}
      >
        <div style={{ maxWidth: 980, margin: "0 auto" }}>
          <div style={{ fontSize: 22, fontWeight: 900 }}>eStamp Pro</div>
          <div style={{ marginTop: 4, opacity: 0.9 }}>
            Secure electronic stamping, verification, and audit trails.
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 980, margin: "0 auto", padding: "38px 24px" }}>
        <a href="/" style={{ color: "#1d4ed8", fontWeight: 700 }}>
          ← Back to eStamp Pro
        </a>

        <section
          style={{
            marginTop: 22,
            background: "#ffffff",
            border: "1px solid #dbe4f0",
            borderRadius: 18,
            padding: 28,
            boxShadow: "0 8px 24px rgba(15,23,42,0.06)",
            lineHeight: 1.7,
          }}
        >
          <h1 style={{ marginTop: 0, fontSize: 38 }}>{title}</h1>
          {subtitle ? <p style={{ color: "#475569" }}>{subtitle}</p> : null}
          {children}
        </section>
      </main>
    </div>
  );
}