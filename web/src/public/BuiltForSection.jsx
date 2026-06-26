import React from "react";

const industries = [
  "Businesses",
  "Government",
  "Legal",
  "Healthcare",
  "Finance",
  "Education",
  "Non-Profits",
  "Service Providers",
];

export default function BuiltForSection() {
  return (
    <section style={{ padding: "70px 24px", background: "#ffffff" }}>
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
          background: "#0f172a",
          color: "#ffffff",
          borderRadius: 28,
          padding: "46px 32px",
          textAlign: "center",
        }}
      >
        <div style={{ color: "#93c5fd", fontWeight: 900 }}>BUILT FOR</div>

        <h2 style={{ fontSize: 40, margin: "10px 0 14px" }}>
          Organizations that value trust.
        </h2>

        <p
          style={{
            color: "#cbd5e1",
            fontSize: 18,
            maxWidth: 720,
            margin: "0 auto 28px",
            lineHeight: 1.7,
          }}
        >
          eStamp Pro is built for teams that need professional, verifiable, and
          auditable digital document workflows.
        </p>

        <div
          style={{
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            justifyContent: "center",
          }}
        >
          {industries.map((item) => (
            <div
              key={item}
              style={{
                background: "rgba(255,255,255,0.10)",
                border: "1px solid rgba(255,255,255,0.18)",
                color: "#ffffff",
                padding: "10px 16px",
                borderRadius: 999,
                fontWeight: 800,
              }}
            >
              {item}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}