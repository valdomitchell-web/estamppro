import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function RefundPolicyPage() {
  return (
    <PublicPageShell
      title="Refund Policy"
      subtitle="Last updated: June 2026"
    >
      <h2>Subscriptions</h2>

      <p>
        eStamp Pro subscriptions are billed monthly unless otherwise stated.
      </p>

      <h2>Cancellation</h2>

      <p>
        Customers may cancel future renewals at any time through the billing
        portal or by contacting support.
      </p>

      <h2>Refund Requests</h2>

      <p>
        Refund requests are reviewed individually for duplicate payments,
        billing errors, or service issues.
      </p>

      <h2>Digital Services</h2>

      <p>
        Because eStamp Pro provides immediate access to digital services,
        refunds are generally not issued for partially used subscription
        periods unless required by applicable law.
      </p>

      <h2>Contact</h2>

      <p>
        For billing assistance, please contact our support team with your
        account email and organization name.
      </p>
    </PublicPageShell>
  );
}