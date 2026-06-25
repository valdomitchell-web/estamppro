import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function PrivacyPage() {
  return (
    <PublicPageShell
      title="Privacy Policy"
      subtitle="Last updated: June 2026"
    >
      <h2>Information We Collect</h2>

      <ul>
        <li>Account information</li>
        <li>Organization information</li>
        <li>Uploaded documents</li>
        <li>Electronic stamps</li>
        <li>Electronic signatures</li>
        <li>Audit logs</li>
        <li>Verification records</li>
      </ul>

      <h2>How We Use Information</h2>

      <p>
        Information is used solely to operate the eStamp Pro platform,
        authenticate users, verify documents, generate certificates, maintain
        audit trails, improve services, and communicate with customers.
      </p>

      <h2>Sharing</h2>

      <p>
        We do not sell customer data. Information may be shared only with
        trusted service providers such as hosting, storage, email, and payment
        processors as required to deliver the service.
      </p>

      <h2>Security</h2>

      <p>
        Documents, verification records, and user accounts are protected using
        industry-standard security measures.
      </p>

      <h2>Contact</h2>

      <p>
        Questions regarding privacy may be submitted through our support email.
      </p>
    </PublicPageShell>
  );
}