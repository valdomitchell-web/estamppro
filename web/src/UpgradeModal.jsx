import React from "react";

const featureContent = {
  pro_branding: {
    title: "Unlock Branding & Exports",
    description:
      "Upgrade to Pro to remove platform watermarking, export branded analytics, and unlock organization branding tools.",
    plan: "pro",
    bullets: [
      "Branded PDF and CSV exports",
      "Organization branding controls",
      "Preset logo overlays and real stamp uploads",
    ],
    cta: "Upgrade to Pro",
  },
  business_reports: {
    title: "Unlock Weekly Analytics Reports",
    description:
      "Upgrade to Business to automate branded analytics delivery for your team and keep report history available in one place.",
    plan: "business",
    bullets: [
      "Automatic weekly PDF reports",
      "Report history and audit visibility",
      "Operational analytics for teams",
    ],
    cta: "Upgrade to Business",
  },
  business_zip: {
    title: "Unlock ZIP Export",
    description:
      "Upgrade to Business to download all stamped files in one ZIP instead of handling them one by one.",
    plan: "business",
    bullets: [
      "Batch ZIP downloads",
      "Faster document handoff",
      "Best for high-volume workflows",
    ],
    cta: "Upgrade to Business",
  },
  pro_email: {
    title: "Unlock Server-side Email Sending",
    description:
      "Upgrade to Pro to send branded verification emails directly from eStamp Pro instead of sharing links manually.",
    plan: "pro",
    bullets: [
      "Server-side branded email sending",
      "Delivery history",
      "Verification link sharing at scale",
    ],
    cta: "Upgrade to Pro",
  },
  business_api: {
    title: "Unlock API Access",
    description:
      "Upgrade to Business to generate API keys and connect eStamp Pro to internal systems or automations.",
    plan: "business",
    bullets: [
      "Generate API keys",
      "Integrate with internal workflows",
      "Business-grade automation access",
    ],
    cta: "Upgrade to Business",
  },
  business_team: {
    title: "Unlock Team Workflows",
    description:
      "Upgrade to Business to invite teammates and manage organization-level collaboration.",
    plan: "business",
    bullets: [
      "Invite team members",
      "Shared organization workflows",
      "Better operational control",
    ],
    cta: "Upgrade to Business",
  },
};

export default function UpgradeModal({ open, featureKey, onClose, onUpgrade }) {
  if (!open) return null;

  const data = featureContent[featureKey] || featureContent.pro_branding;

  return (
    <div style={overlayStyle} onClick={onClose}>
      <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ fontSize: 12, fontWeight: 800, color: "#1d4ed8", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>
          Upgrade available
        </div>

        <h2 style={{ margin: "0 0 10px 0", fontSize: 28, color: "#0f172a" }}>
          {data.title}
        </h2>

        <p style={{ margin: "0 0 16px 0", color: "#475569", lineHeight: 1.6 }}>
          {data.description}
        </p>

        <div
          style={{
            display: "inline-block",
            background: "#eff6ff",
            color: "#1d4ed8",
            border: "1px solid #bfdbfe",
            padding: "6px 12px",
            borderRadius: 999,
            fontWeight: 700,
            marginBottom: 16,
          }}
        >
          Requires {data.plan === "business" ? "Business" : "Pro"}
        </div>

        <ul style={{ margin: "0 0 22px 18px", color: "#334155", lineHeight: 1.8 }}>
          {data.bullets.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button
            onClick={() => onUpgrade?.(data.plan)}
            style={{
              background: "#1d4ed8",
              color: "#fff",
              border: "none",
              borderRadius: 10,
              padding: "10px 16px",
              cursor: "pointer",
              fontWeight: 700,
              boxShadow: "0 2px 8px rgba(29, 78, 216, 0.18)",
            }}
          >
            {data.cta}
          </button>

          <button
            onClick={onClose}
            style={{
              background: "#eff6ff",
              color: "#1d4ed8",
              border: "1px solid #bfdbfe",
              borderRadius: 10,
              padding: "10px 16px",
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            Maybe later
          </button>
        </div>
      </div>
    </div>
  );
}

const overlayStyle = {
  position: "fixed",
  inset: 0,
  background: "rgba(15, 23, 42, 0.55)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 20,
  zIndex: 9999,
};

const modalStyle = {
  width: "100%",
  maxWidth: 560,
  background: "#fff",
  borderRadius: 18,
  padding: 26,
  boxShadow: "0 24px 64px rgba(15,23,42,0.25)",
};