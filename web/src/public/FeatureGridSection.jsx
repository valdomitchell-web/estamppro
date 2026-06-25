import React from "react";

const features = [
  ["Electronic Stamping", "Securely apply official business stamps to PDF documents."],
  ["QR Verification", "Let recipients instantly confirm document authenticity."],
  ["Digital Certificates", "Generate branded certificates for verified documents."],
  ["Audit Trail", "Track uploads, stamping, sharing, verification, and team actions."],
  ["Team Collaboration", "Invite users and manage organization-level roles."],
  ["API Integration", "Automate stamping and verification workflows securely."],
];

export default function FeatureGridSection() {
  return (
    <section style={{ padding: "76px 24px", background: "#f8fafc" }}>
      <div style={{ maxWidth: 1120, margin: "0 auto" }}>
        <div style={{ textAlign: "center", maxWidth: 760, margin: "0 auto 42px" }}>
          <div style={{ color: "#1d4ed8", fontWeight: 900 }}>FEATURES</div>
          <h2 style={{ fontSize: 42, margin: "10px 0", color: "#0f172a" }}>
            Everything needed to build document trust.
          </h2>
          <p style={{ color: "#475569", fontSize: 18 }}>
            From electronic stamping to verification certificates, eStamp Pro gives organizations a complete trust workflow.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 18 }}>
          {features.map(([title, text]) => (
            <div
              key={title}
              style={{
                background: "#ffffff",
                border: "1px solid #dbe4f0",
                borderRadius: 20,
                padding: 26,
                boxShadow: "0 8px 24px rgba(15,23,42,0.04)",
              }}
            >
              <h3 style={{ marginTop: 0, color: "#0f172a" }}>{title}</h3>
              <p style={{ color: "#475569", lineHeight: 1.65, marginBottom: 0 }}>{text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}