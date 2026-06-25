import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function AboutPage() {
  return (
    <PublicPageShell
      title="About eStamp Pro"
      subtitle="Secure electronic stamping, verification, and audit trails for modern businesses."
    >
      <p>
        eStamp Pro is a cloud-based platform that helps organizations apply
        secure electronic stamps and signatures to PDF documents, verify
        stamped records, and maintain clear audit trails.
      </p>

      <h2>What We Do</h2>
      <p>
        We provide tools for electronic document stamping, QR-based
        verification, certificate generation, branded verification pages,
        analytics, team access, and API-based workflows.
      </p>

      <h2>Who We Serve</h2>
      <p>
        eStamp Pro is designed for businesses, administrators, service
        providers, compliance teams, and organizations that need a reliable way
        to stamp, share, and verify documents.
      </p>

      <h2>Our Goal</h2>
      <p>
        Our goal is to make document verification simple, professional, and
        accessible while helping organizations reduce manual stamping,
        improve trust, and maintain better records.
      </p>

      <h2>Contact</h2>
      <p>
        For questions, support, or business inquiries, please contact the eStamp
        Pro support team through the email provided in your account or
        verification pages.
      </p>
    </PublicPageShell>
  );
}