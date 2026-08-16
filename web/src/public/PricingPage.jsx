import React from "react";
import PublicPageShell from "./PublicPageShell";

const card = {
  background: "#fff",
  border: "1px solid #dbe4f0",
  borderRadius: 16,
  padding: 24,
  flex: 1,
  minWidth: 260,
};

const button = {
  marginTop: 20,
  background: "#1d4ed8",
  color: "#fff",
  border: "none",
  borderRadius: 10,
  padding: "12px 18px",
  cursor: "pointer",
  fontWeight: 700,
  width: "100%",
};

export default function PricingPage() {
  return (
    <PublicPageShell
      title="Simple, Transparent Pricing"
      subtitle="Choose the plan that best fits your organization."
    >
      <div
        style={{
          display: "flex",
          gap: 20,
          flexWrap: "wrap",
          marginTop: 24,
        }}
      >
        <div style={card}>
          <h2>Free</h2>
          <h1>$0</h1>

          <ul>
            <li>Create stamps</li>
            <li>Apply electronic stamps</li>
            <li>Document verification</li>
            <li>QR verification</li>
            <li>Certificate generation</li>
          </ul>

          <a
  href="https://app.estamppro.com/?auth=register&fresh=1"
  style={{ textDecoration: "none" }}
>
  <button style={button}>Start Free</button>
</a>
        </div>

        <div
          style={{
            ...card,
            border: "2px solid #1d4ed8",
          }}
        >
          <h2>Pro</h2>
          <h1>$19/month</h1>

          <ul>
            <li>Everything in Free</li>
            <li>Brand customization</li>
            <li>Email sharing</li>
            <li>Analytics dashboard</li>
            <li>CSV & PDF exports</li>
          </ul>

          <a
  href="https://app.estamppro.com/?auth=register&fresh=1"
  style={{ textDecoration: "none" }}
>
  <button style={button}>Start with Pro</button>
</a>
        </div>

        <div style={card}>
          <h2>Business</h2>
          <h1>$59/month</h1>

          <ul>
            <li>Everything in Pro</li>
            <li>Teams</li>
            <li>API Keys</li>
            <li>Weekly Reports</li>
            <li>Advanced Branding</li>
            <li>Business Signatures</li>
          </ul>

          <a
  href="https://app.estamppro.com/?auth=register&fresh=1"
  style={{ textDecoration: "none" }}
>
  <button style={button}>Start with Business</button>
</a>
        </div>
      </div>
    </PublicPageShell>
  );
}