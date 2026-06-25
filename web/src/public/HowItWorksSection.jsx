import React from "react";

const steps = [
  ["1", "Upload PDF", "Add the document you need to stamp."],
  ["2", "Apply eStamp", "Place your official electronic stamp."],
  ["3", "Verify QR", "Recipients verify authenticity instantly."],
  ["4", "Generate Certificate", "Download professional proof of verification."],
];

export default function HowItWorksSection() {
  return (
    <section style={{ padding: "76px 24px", background: "#ffffff" }}>
      <div style={{ maxWidth: 1120, margin: "0 auto" }}>
        <div style={{ textAlign: "center", maxWidth: 720, margin: "0 auto 42px" }}>
          <div style={{ color: "#1d4ed8", fontWeight: 900 }}>HOW IT WORKS</div>
          <h2 style={{ fontSize: 42, margin: "10px 0", color: "#0f172a" }}>
            From upload to verified certificate in minutes.
          </h2>
          <p style={{ color: "#475569", fontSize: 18 }}>
            eStamp Pro keeps the document workflow simple while maintaining a trusted audit trail.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 18 }}>
          {steps.map(([number, title, text]) => (
            <div
              key={title}
              style={{
                background: "#f8fafc",
                border: "1px solid #e2e8f0",
                borderRadius: 20,
                padding: 24,
                boxShadow: "0 8px 24px rgba(15,23,42,0.04)",
              }}
            >
              <div
                style={{
                  width: 42,
                  height: 42,
                  borderRadius: 14,
                  background: "#1d4ed8",
                  color: "#fff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 900,
                  marginBottom: 16,
                }}
              >
                {number}
              </div>
              <h3 style={{ margin: "0 0 8px", color: "#0f172a" }}>{title}</h3>
              <p style={{ margin: 0, color: "#475569", lineHeight: 1.6 }}>{text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}