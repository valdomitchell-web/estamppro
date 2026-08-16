import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function PrivacyPage() {
  return (
    <PublicPageShell
      title="Privacy Policy"
      subtitle="Last updated: August 2026"
    >
      <h2>Information We Collect</h2>
      <p>
        We collect information necessary to provide and operate eStamp Pro.
        Depending on how you use the service, this may include:
      </p>

      <ul>
        <li>Account information, such as your name and email address</li>
        <li>Organization and team information</li>
        <li>Uploaded documents</li>
        <li>Electronic stamps and signatures</li>
        <li>Audit logs and activity records</li>
        <li>Document verification and certificate records</li>
        <li>Usage and technical information related to the service</li>
        <li>Subscription and billing status information</li>
      </ul>

      <h2>How We Use Information</h2>
      <p>
        We use information to provide, secure, maintain, and improve eStamp Pro,
        including to authenticate users, process documents, apply electronic
        stamps and signatures, provide document verification, generate
        certificates, maintain audit trails, provide analytics, manage
        subscriptions, provide customer support, and communicate about the
        service.
      </p>

      <h2>Documents and Customer Content</h2>
      <p>
        Documents, stamps, signatures, and other content submitted to eStamp Pro
        are processed as necessary to provide the features requested by the
        customer. Customers are responsible for ensuring they have the
        appropriate authority to upload and process content through the service.
      </p>

      <h2>Payments</h2>
      <p>
        Subscription payments are processed through third-party payment
        providers. eStamp Pro may receive information about your subscription,
        transaction status, and billing account, but payment credentials are
        handled by the applicable payment provider.
      </p>

      <h2>Service Providers</h2>
      <p>
        We may share or process information with trusted service providers that
        help us operate eStamp Pro, including providers of cloud hosting,
        storage, email delivery, analytics, and payment processing. These
        providers receive information only as necessary to perform services on
        our behalf.
      </p>

      <h2>Data Sales</h2>
      <p>
        We do not sell customer documents or personal information.
      </p>

      <h2>Security</h2>
      <p>
        We use reasonable technical and organizational safeguards designed to
        protect accounts, documents, verification records, and other information
        processed through eStamp Pro. No internet-based service can guarantee
        absolute security.
      </p>

      <h2>Data Retention</h2>
      <p>
        We retain information for as long as reasonably necessary to provide
        the service, maintain security and audit records, comply with legal
        obligations, resolve disputes, and enforce our agreements. Retention
        periods may vary depending on the type of information and the features
        used.
      </p>

      <h2>Your Requests</h2>
      <p>
        You may contact us to request assistance with your account or questions
        regarding personal information associated with your account. Some
        records may need to be retained where required for security, fraud
        prevention, legal compliance, or legitimate audit purposes.
      </p>

      <h2>Changes to This Policy</h2>
      <p>
        We may update this Privacy Policy as eStamp Pro evolves. The updated
        version will be posted on this page with a revised "Last updated" date.
      </p>

      <h2>Contact</h2>
      <p>
        Privacy questions may be sent to{" "}
        <a href="mailto:support@estamppro.com">
          support@estamppro.com
        </a>.
      </p>
    </PublicPageShell>
  );
}