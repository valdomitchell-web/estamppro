import React from "react";
import PublicPageShell from "./PublicPageShell.jsx";

export default function ContactPage() {
  return (
    <PublicPageShell
      title="Contact"
      subtitle="Need help with eStamp Pro? Contact our support team."
    >
      <h2>Support</h2>
      <p>Email: support@estamppro.com</p>

      <h2>Sales</h2>
      <p>Email: support@estamppro.com</p>

      <h2>Business Location</h2>
      <p>Grenada</p>

      <h2>Response Time</h2>
      <p>We usually respond within 1–2 business days.</p>
    </PublicPageShell>
  );
}