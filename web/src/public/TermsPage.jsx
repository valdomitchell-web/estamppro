import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function TermsPage() {
  return (
    <PublicPageShell
      title="Terms of Service"
      subtitle="Last updated: August 2026"
    >
      <h2>Acceptance</h2>
      <p>
        By creating an account or accessing or using eStamp Pro, you agree to
        these Terms of Service. If you use eStamp Pro on behalf of an
        organization, you represent that you are authorized to use the service
        on its behalf.
      </p>

      <h2>Service</h2>
      <p>
        eStamp Pro provides cloud-based electronic document stamping,
        verification, audit trails, certificate generation, analytics, team
        features, API access, and related services depending on your plan.
      </p>

      <h2>Accounts and Security</h2>
      <p>
        Users are responsible for maintaining the security of their accounts,
        passwords, electronic signatures, stamps, and API keys and for activity
        performed through their accounts. You should notify us promptly if you
        believe your account has been accessed without authorization.
      </p>

      <h2>Authorized Use</h2>
      <p>
        You may only upload, stamp, sign, share, or otherwise process documents
        and content that you are authorized to manage. You are responsible for
        the documents and information you submit to eStamp Pro.
      </p>

      <h2>Prohibited Use</h2>
      <p>
        You may not use eStamp Pro for fraud, unlawful activity, unauthorized
        document alteration, impersonation, infringement of another person's
        rights, attempts to compromise the platform, or activity that interferes
        with the security or operation of the service.
      </p>

      <h2>Subscriptions and Billing</h2>
      <p>
        Paid plans are billed according to the price and billing period
        presented at the time of purchase. Subscriptions renew automatically
        unless cancelled before the next renewal, subject to the terms of the
        applicable payment provider.
      </p>

      <h2>Cancellation</h2>
      <p>
        Customers may cancel future subscription renewals through the available
        billing controls or by contacting support. Access to paid features may
        remain available through the applicable paid subscription period.
        Refund eligibility is governed by our Refund Policy and applicable law.
      </p>

      <h2>Service Availability</h2>
      <p>
        We work to keep eStamp Pro reliable and available, but uninterrupted or
        error-free operation cannot be guaranteed. Maintenance, security
        updates, third-party service interruptions, or circumstances outside
        our reasonable control may occasionally affect availability.
      </p>

      <h2>Intellectual Property</h2>
      <p>
        eStamp Pro and its software, branding, website content, and related
        platform materials are protected by applicable intellectual property
        laws. Customers retain responsibility for and any rights they hold in
        documents, stamps, logos, signatures, and other content they submit to
        the service.
      </p>

      <h2>Suspension and Termination</h2>
      <p>
        We may restrict or suspend access where reasonably necessary to address
        fraud, abuse, unlawful activity, security threats, violations of these
        Terms, or risks to the platform or other users.
      </p>

      <h2>Document Validity</h2>
      <p>
        eStamp Pro provides technology for electronic stamping, verification,
        certificates, and audit purposes. Customers remain responsible for
        determining whether a document, stamp, signature, or transaction meets
        their legal, regulatory, contractual, or organizational requirements.
      </p>

      <h2>Limitation of Liability</h2>
      <p>
        To the extent permitted by applicable law, eStamp Pro is not responsible
        for losses resulting from unauthorized customer use, customer-provided
        content, third-party services, or decisions made based solely on the
        platform's verification information. Nothing in these Terms excludes
        liability that cannot legally be excluded.
      </p>

      <h2>Changes to These Terms</h2>
      <p>
        We may update these Terms as the service evolves. Updated Terms will be
        posted on this page with a revised "Last updated" date.
      </p>

      <h2>Contact</h2>
      <p>
        Questions about these Terms may be sent to{" "}
        <a href="mailto:support@estamppro.com">
          support@estamppro.com
        </a>.
      </p>
    </PublicPageShell>
  );
}