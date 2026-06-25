import React from "react";
import PublicPageShell from "./PublicPageShell.jsx";

const features = [
  ["Electronic Stamping", "Apply secure electronic business stamps to PDF documents."],
  ["QR Verification", "Allow recipients to verify stamped documents instantly."],
  ["Verification Certificates", "Generate branded certificates for verified documents."],
  ["Audit Trail", "Track uploads, stamping, sharing, verification, and team actions."],
  ["Team Management", "Invite teammates and manage organization roles."],
  ["API Access", "Automate document workflows with secure API keys."],
];

export default function FeaturesPage() {
  return (
    <PublicPageShell
      title="Features"
      subtitle="Everything your organization needs to stamp, verify, and audit documents."
    >
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 18 }}>
        {features.map(([title, text]) => (
          <div key={title} style={{ border: "1px solid #dbe4f0", borderRadius: 16, padding: 22 }}>
            <h2 style={{ marginTop: 0 }}>{title}</h2>
            <p style={{ color: "#475569" }}>{text}</p>
          </div>
        ))}
      </div>
    </PublicPageShell>
  );
}