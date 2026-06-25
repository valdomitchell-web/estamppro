import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function TermsPage() {
  return (
    <PublicPageShell
      title="Terms of Service"
      subtitle="Last updated: June 2026"
    >
      <h2>Acceptance</h2>

      <p>
        By accessing or using eStamp Pro, you agree to these Terms of Service.
      </p>

      <h2>Service</h2>

      <p>
        eStamp Pro provides cloud-based electronic document stamping,
        verification, audit trails, certificate generation, analytics, and
        related services.
      </p>

      <h2>Accounts</h2>

      <p>
        Users are responsible for maintaining the security of their accounts,
        passwords, signatures, stamps, and API keys.
      </p>

      <h2>Acceptable Use</h2>

      <p>
        You may only stamp and verify documents that you are authorized to
        manage.
      </p>

      <h2>Suspension</h2>

      <p>
        We may suspend accounts involved in fraud, abuse, illegal activities,
        or attempts to compromise the platform.
      </p>

      <h2>Limitation of Liability</h2>

      <p>
        eStamp Pro provides technology for document verification and audit
        purposes. Customers remain responsible for the legal validity and
        contents of their documents.
      </p>
    </PublicPageShell>
  );
}