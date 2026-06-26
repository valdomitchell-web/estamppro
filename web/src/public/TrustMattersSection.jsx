import React from "react";

export default function TrustMattersSection() {
  return (
    <section
      style={{
        padding: "90px 24px",
        background: "linear-gradient(135deg, #eff6ff 0%, #ffffff 100%)",
      }}
    >
      <div
        style={{
          maxWidth: 980,
          margin: "0 auto",
          textAlign: "center",
        }}
      >
        <div
          style={{
            color: "#1d4ed8",
            fontWeight: 900,
            letterSpacing: 1,
            marginBottom: 12,
          }}
        >
          WHY TRUST MATTERS
        </div>

        <h2
          style={{
            fontSize: 46,
            lineHeight: 1.1,
            margin: "0 0 24px",
            color: "#0f172a",
          }}
        >
          Every important document depends on trust.
        </h2>

        <p
          style={{
            fontSize: 20,
            lineHeight: 1.8,
            color: "#475569",
            maxWidth: 820,
            margin: "0 auto 30px",
          }}
        >
          Contracts, certificates, reports, approvals, and official records all
          need confidence. eStamp Pro helps organizations protect that trust
          through secure electronic stamping, QR verification, digital
          certificates, and complete audit trails.
        </p>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
            gap: 12,
            marginTop: 34,
          }}
        >
          {[
            "Contracts",
            "Certificates",
            "Reports",
            "Approvals",
            "Official Records",
            "Shared Documents",
          ].map((item) => (
            <span
              key={item}
              style={{
                background: "#ffffff",
                border: "1px solid #bfdbfe",
                color: "#1d4ed8",
                padding: "10px 16px",
                borderRadius: 999,
                fontWeight: 800,
              }}
            >
              {item}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}