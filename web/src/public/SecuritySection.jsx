import React from "react";

const items = [
  {
    title: "Enterprise Security",
    text: "Protect your documents with modern security practices and encrypted communication.",
  },
  {
    title: "QR Verification",
    text: "Recipients can instantly verify document authenticity using a secure QR code.",
  },
  {
    title: "Digital Certificates",
    text: "Generate professional verification certificates for every verified document.",
  },
  {
    title: "Complete Audit Trail",
    text: "Track uploads, stamping, sharing, verification, and administrative actions.",
  },
  {
    title: "Role-Based Access",
    text: "Assign permissions for owners, administrators, staff, and verification users.",
  },
  {
    title: "Cloud Storage",
    text: "Securely manage documents and verification records from anywhere.",
  },
];

export default function SecuritySection() {
  return (
    <section
      style={{
        padding: "80px 24px",
        background: "#0f172a",
        color: "#fff",
      }}
    >
      <div style={{ maxWidth: 1120, margin: "0 auto" }}>
        <div
          style={{
            textAlign: "center",
            maxWidth: 760,
            margin: "0 auto 48px",
          }}
        >
          <div
            style={{
              color: "#60a5fa",
              fontWeight: 900,
              letterSpacing: 1,
            }}
          >
            SECURITY
          </div>

          <h2
            style={{
              fontSize: 44,
              margin: "12px 0",
            }}
          >
            Built for organizations that demand trust.
          </h2>

          <p
            style={{
              color: "#cbd5e1",
              fontSize: 18,
              lineHeight: 1.8,
            }}
          >
            Every feature in eStamp Pro is designed to help organizations
            confidently stamp, verify, and protect important digital documents.
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))",
            gap: 22,
          }}
        >
          {items.map((item) => (
            <div
              key={item.title}
              style={{
                background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.10)",
                borderRadius: 22,
                padding: 28,
              }}
            >
              <div
                style={{
                  width: 52,
                  height: 52,
                  borderRadius: 16,
                  background: "#1d4ed8",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 24,
                  marginBottom: 18,
                }}
              >
                🛡️
              </div>

              <h3
                style={{
                  marginTop: 0,
                  marginBottom: 12,
                  color: "#fff",
                }}
              >
                {item.title}
              </h3>

              <p
                style={{
                  margin: 0,
                  color: "#cbd5e1",
                  lineHeight: 1.7,
                }}
              >
                {item.text}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}