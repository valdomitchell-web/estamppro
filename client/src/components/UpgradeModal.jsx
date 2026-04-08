import React from "react";

export default function UpgradeModal({ open, onClose, feature }) {
  if (!open) return null;

  const content = {
    pdf_export: {
      title: "Unlock PDF Export",
      description:
        "Export branded analytics reports as PDF documents for sharing and compliance.",
      plan: "Pro",
    },
    zip_export: {
      title: "Unlock ZIP Export",
      description:
        "Download all stamped documents at once and save hours of manual work.",
      plan: "Business",
    },
    weekly_reports: {
      title: "Automate Weekly Reports",
      description:
        "Send branded analytics reports automatically to your team every week.",
      plan: "Business",
    },
    branding: {
      title: "Unlock Custom Branding",
      description:
        "Add your logo, colors, and custom footer to all documents and emails.",
      plan: "Pro",
    },
  };

  const data = content[feature] || content["pdf_export"];

  return (
    <div style={overlay}>
      <div style={modal}>
        <h2>{data.title}</h2>
        <p style={{ marginBottom: 20 }}>{data.description}</p>

        <div style={badge}>
          Requires {data.plan} plan
        </div>

        <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
          <button style={primaryBtn} onClick={() => window.location.href = "/billing"}>
            Upgrade Now
          </button>

          <button style={secondaryBtn} onClick={onClose}>
            Maybe later
          </button>
        </div>
      </div>
    </div>
  );
}

const overlay = {
  position: "fixed",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  background: "rgba(0,0,0,0.6)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 9999,
};

const modal = {
  background: "#fff",
  padding: 30,
  borderRadius: 12,
  width: 400,
  maxWidth: "90%",
  boxShadow: "0 10px 30px rgba(0,0,0,0.2)",
};

const badge = {
  background: "#eef2ff",
  color: "#1d4ed8",
  padding: "6px 12px",
  borderRadius: 8,
  display: "inline-block",
  fontWeight: "bold",
};

const primaryBtn = {
  background: "#2563eb",
  color: "#fff",
  padding: "10px 16px",
  borderRadius: 8,
  border: "none",
  cursor: "pointer",
};

const secondaryBtn = {
  background: "#e5e7eb",
  padding: "10px 16px",
  borderRadius: 8,
  border: "none",
  cursor: "pointer",
};