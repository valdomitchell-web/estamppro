import React from "react";

export default function HeroSection() {
  return (
    <section
      style={{
        background:
          "linear-gradient(135deg, #eff6ff 0%, #ffffff 45%, #f8fafc 100%)",
        padding: "76px 24px",
      }}
    >
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 44,
          alignItems: "center",
        }}
      >
        <div>
          <div
            style={{
              display: "inline-block",
              background: "#dbeafe",
              color: "#1d4ed8",
              padding: "8px 14px",
              borderRadius: 999,
              fontWeight: 800,
              marginBottom: 18,
            }}
          >
            Document Trust Platform
          </div>

          <h1
            style={{
              fontSize: 56,
              lineHeight: 1.05,
              margin: "0 0 20px",
              color: "#0f172a",
              letterSpacing: "-1.5px",
            }}
          >
            Build Trust Into Every Document
          </h1>

          <p
            style={{
              fontSize: 19,
              lineHeight: 1.7,
              color: "#475569",
              maxWidth: 620,
              marginBottom: 30,
            }}
          >
            eStamp Pro helps organizations securely stamp, verify, certify, and
            audit PDF documents with QR verification, digital certificates, and
            professional audit trails.
          </p>

          <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
            <a
              href="/"
              style={{
                background: "#1d4ed8",
                color: "#fff",
                textDecoration: "none",
                padding: "14px 20px",
                borderRadius: 12,
                fontWeight: 900,
              }}
            >
              Start Free
            </a>

            <a
              href="/pricing"
              style={{
                background: "#ffffff",
                color: "#1d4ed8",
                textDecoration: "none",
                padding: "14px 20px",
                borderRadius: 12,
                fontWeight: 900,
                border: "1px solid #bfdbfe",
              }}
            >
              View Pricing
            </a>
          </div>

          <div
            style={{
              marginTop: 28,
              color: "#64748b",
              fontWeight: 700,
            }}
          >
            Trusted for secure digital document workflows.
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #dbe4f0",
            borderRadius: 24,
            padding: 28,
            boxShadow: "0 20px 45px rgba(15,23,42,0.10)",
          }}
        >
          <div
            style={{
              background: "#f8fafc",
              border: "1px solid #e2e8f0",
              borderRadius: 18,
              padding: 22,
            }}
          >
            <JourneyStep number="1" title="Upload PDF" text="Add your document" />
            <Arrow />
            <JourneyStep number="2" title="Apply Stamp" text="Place your secure eStamp" />
            <Arrow />
            <JourneyStep number="3" title="QR Verify" text="Recipients verify instantly" />
            <Arrow />
            <JourneyStep number="4" title="Certificate" text="Generate proof of verification" />
          </div>
        </div>
      </div>
    </section>
  );
}

function JourneyStep({ number, title, text }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        background: "#ffffff",
        border: "1px solid #e2e8f0",
        borderRadius: 16,
        padding: 16,
      }}
    >
      <div
        style={{
          width: 38,
          height: 38,
          borderRadius: 12,
          background: "#1d4ed8",
          color: "#ffffff",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 900,
        }}
      >
        {number}
      </div>

      <div>
        <div style={{ fontWeight: 900, color: "#0f172a" }}>{title}</div>
        <div style={{ color: "#64748b", fontSize: 14 }}>{text}</div>
      </div>
    </div>
  );
}

function Arrow() {
  return (
    <div
      style={{
        textAlign: "center",
        color: "#1d4ed8",
        fontWeight: 900,
        padding: "8px 0",
      }}
    >
      ↓
    </div>
  );
}