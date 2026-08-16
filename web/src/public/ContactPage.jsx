import React from "react";
import PublicPageShell from "./PublicPageShell.jsx";

export default function ContactPage() {
  return (
    <PublicPageShell
      title="Contact"
      subtitle="Need help with eStamp Pro? Contact our support team."
    >
      <div
        style={{
          display: "grid",
          gap: 20,
          marginTop: 24,
        }}
      >
        <div
          style={{
            padding: 24,
            border: "1px solid #dbe4f0",
            borderRadius: 16,
            background: "#ffffff",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Customer Support</h2>

          <p style={{ color: "#475569", lineHeight: 1.7 }}>
            Need help with your account, stamping, verification, billing,
            or another eStamp Pro feature? Our support team is here to help.
          </p>

          <p>
            <strong>Email:</strong>{" "}
            <a href="mailto:support@estamppro.com">
              support@estamppro.com
            </a>
          </p>
        </div>

        <div
          style={{
            padding: 24,
            border: "1px solid #dbe4f0",
            borderRadius: 16,
            background: "#ffffff",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Sales & Business Enquiries</h2>

          <p style={{ color: "#475569", lineHeight: 1.7 }}>
            Have questions about Pro, Business, team access, API integration,
            or using eStamp Pro for your organization? Contact us and we'll
            help you choose the right setup.
          </p>

          <p>
            <strong>Email:</strong>{" "}
            <a href="mailto:support@estamppro.com">
              support@estamppro.com
            </a>
          </p>
        </div>

        <div
          style={{
            padding: 24,
            border: "1px solid #dbe4f0",
            borderRadius: 16,
            background: "#f8fafc",
          }}
        >
          <h2 style={{ marginTop: 0 }}>When contacting support</h2>

          <p style={{ color: "#475569", lineHeight: 1.7 }}>
            To help us resolve your request faster, include the email address
            associated with your eStamp Pro account and a brief description
            of the issue.
          </p>

          <p
            style={{
              color: "#475569",
              lineHeight: 1.7,
              marginBottom: 0,
            }}
          >
            For your security, never send passwords, API keys, payment
            credentials, or other sensitive authentication information by
            email.
          </p>
        </div>

        <div
          style={{
            padding: 24,
            border: "1px solid #dbe4f0",
            borderRadius: 16,
            background: "#ffffff",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Response Time</h2>

          <p style={{ color: "#475569", lineHeight: 1.7 }}>
            We usually respond within 1–2 business days.
          </p>

          <h2>Business Location</h2>

          <p style={{ color: "#475569", marginBottom: 0 }}>
            Grenada
          </p>
        </div>
      </div>
    </PublicPageShell>
  );
}