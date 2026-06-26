import React from "react";

const plans = [
  {
    name: "Free",
    price: "$0",
    subtitle: "Perfect for individuals getting started.",
    features: [
      "Electronic Stamping",
      "QR Verification",
      "Verification Certificates",
      "Basic Usage",
    ],
    button: "Start Free",
    featured: false,
  },
  {
    name: "Pro",
    price: "$19",
    subtitle: "For professionals and growing businesses.",
    features: [
      "Everything in Free",
      "Brand Customization",
      "Analytics",
      "PDF & CSV Exports",
      "Email Sharing",
    ],
    button: "Most Popular",
    featured: true,
  },
  {
    name: "Business",
    price: "$59",
    subtitle: "Complete document trust platform.",
    features: [
      "Everything in Pro",
      "Teams",
      "API Access",
      "Weekly Reports",
      "Business Signatures",
      "Advanced Branding",
    ],
    button: "Enterprise Ready",
    featured: false,
  },
];

export default function PricingPreviewSection() {
  return (
   <section id="pricing" style={{ padding: "90px 24px", background: "#ffffff" }}>
      <div
        style={{
          maxWidth: 1120,
          margin: "0 auto",
        }}
      >
        <div
          style={{
            textAlign: "center",
            marginBottom: 55,
          }}
        >
          <div
            style={{
              color: "#1d4ed8",
              fontWeight: 900,
              letterSpacing: 1,
            }}
          >
            PRICING
          </div>

          <h2
            style={{
              fontSize: 44,
              margin: "12px 0",
              color: "#0f172a",
            }}
          >
            Plans that grow with your organization.
          </h2>

          <p
            style={{
              maxWidth: 700,
              margin: "0 auto",
              color: "#475569",
              fontSize: 18,
              lineHeight: 1.8,
            }}
          >
            Start free today and upgrade only when your organization needs
            additional branding, collaboration, reporting, and automation.
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))",
            gap: 28,
          }}
        >
          {plans.map((plan) => (
            <div
              key={plan.name}
              style={{
                background: "#fff",
                border: plan.featured
                  ? "2px solid #2563eb"
                  : "1px solid #dbe4f0",
                borderRadius: 24,
                padding: 34,
                boxShadow: plan.featured
                  ? "0 18px 50px rgba(37,99,235,.15)"
                  : "0 10px 30px rgba(15,23,42,.05)",
                position: "relative",
              }}
            >
              {plan.featured && (
                <div
                  style={{
                    position: "absolute",
                    top: -14,
                    left: 24,
                    background: "#2563eb",
                    color: "#fff",
                    padding: "8px 16px",
                    borderRadius: 999,
                    fontWeight: 800,
                    fontSize: 13,
                  }}
                >
                  MOST POPULAR
                </div>
              )}

              <h3
                style={{
                  marginTop: 10,
                  marginBottom: 0,
                  color: "#0f172a",
                  fontSize: 28,
                }}
              >
                {plan.name}
              </h3>

              <div
                style={{
                  fontSize: 52,
                  fontWeight: 900,
                  color: "#1d4ed8",
                  marginTop: 12,
                }}
              >
                {plan.price}
              </div>

              <div
                style={{
                  color: "#64748b",
                  marginBottom: 24,
                }}
              >
                {plan.subtitle}
              </div>

              {plan.features.map((feature) => (
                <div
                  key={feature}
                  style={{
                    display: "flex",
                    gap: 10,
                    marginBottom: 14,
                    color: "#334155",
                  }}
                >
                  <span style={{ color: "#16a34a", fontWeight: 900 }}>✓</span>

                  <span>{feature}</span>
                </div>
              ))}

              <a
               href="/#pricing"
                style={{
                  display: "block",
                  textAlign: "center",
                  marginTop: 28,
                  background: plan.featured ? "#2563eb" : "#0f172a",
                  color: "#fff",
                  textDecoration: "none",
                  padding: "14px",
                  borderRadius: 14,
                  fontWeight: 800,
                }}
              >
                {plan.button}
              </a>
            </div>
          ))}
        </div>

        <div
          style={{
            textAlign: "center",
            marginTop: 50,
          }}
        >
         <a href="/#pricing">
          
            View Full Pricing →
          </a>
        </div>
      </div>
    </section>
  );
}