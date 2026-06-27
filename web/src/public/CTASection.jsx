import React from "react";

export default function CTASection() {
  return (
    <section
      style={{
        padding: "100px 24px",
        background:
          "linear-gradient(135deg,#1d4ed8 0%,#2563eb 50%,#3b82f6 100%)",
        color: "#fff",
        textAlign: "center",
      }}
    >
      <div
        style={{
          maxWidth: 860,
          margin: "0 auto",
        }}
      >
        <div
          style={{
            fontWeight: 900,
            letterSpacing: 1,
            opacity: .9,
            marginBottom: 14,
          }}
        >
          START TODAY
        </div>

        <h2
          style={{
            fontSize: 52,
            lineHeight: 1.1,
            marginBottom: 22,
          }}
        >
          Build Trust Into Every Document.
        </h2>

        <p
          style={{
            fontSize: 20,
            lineHeight: 1.8,
            maxWidth: 720,
            margin: "0 auto 36px",
            opacity: .95,
          }}
        >
          Whether you're a small business or a growing enterprise,
          eStamp Pro helps your organization stamp, verify,
          certify and protect every important document.
        </p>

        <div
          style={{
            display: "flex",
            justifyContent: "center",
            gap: 18,
            flexWrap: "wrap",
          }}
        >
         <a href="https://app.estamppro.com/?auth=register"
            style={{
              background: "#fff",
              color: "#2563eb",
              padding: "16px 26px",
              borderRadius: 14,
              textDecoration: "none",
              fontWeight: 900,
              fontSize: 18,
            }}
          >
            Start Free
          </a>

          <a href="/#pricing"
            style={{
              border: "2px solid rgba(255,255,255,.45)",
              color: "#fff",
              padding: "16px 26px",
              borderRadius: 14,
              textDecoration: "none",
              fontWeight: 900,
              fontSize: 18,
            }}
          >
            View Pricing
          </a>
        </div>

        <div
          style={{
            marginTop: 50,
            display: "flex",
            justifyContent: "center",
            gap: 22,
            flexWrap: "wrap",
            fontWeight: 700,
            opacity: .95,
          }}
        >
          <span>✓ Secure Stamping</span>
          <span>✓ QR Verification</span>
          <span>✓ Digital Certificates</span>
          <span>✓ Audit Trail</span>
        </div>
      </div>
    </section>
  );
}