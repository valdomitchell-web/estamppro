import React from "react";
import PublicPageShell from "./PublicPageShell";

export default function RefundPolicyPage() {
  return (
    <PublicPageShell
      title="Refund & Cancellation Policy"
      subtitle="Last updated: August 2026"
    >
      <h2>Subscriptions</h2>
      <p>
        eStamp Pro paid subscriptions are billed monthly unless otherwise
        stated at the time of purchase. Subscription pricing and the applicable
        billing period are displayed before purchase.
      </p>

      <h2>Automatic Renewal</h2>
      <p>
        Paid subscriptions may renew automatically at the end of each billing
        period unless cancelled before the next renewal date.
      </p>

      <h2>Cancellation</h2>
      <p>
        Customers may cancel future renewals using the available billing
        controls or by contacting support. Cancellation prevents future
        renewals but does not normally result in an automatic refund for the
        current paid subscription period.
      </p>

      <p>
        Where applicable, access to paid features may continue until the end of
        the already-paid subscription period.
      </p>

      <h2>Refund Requests</h2>
      <p>
        Refund requests are reviewed individually. Refunds may be considered
        for circumstances such as duplicate charges, confirmed billing errors,
        or significant service issues.
      </p>

      <h2>Digital Services</h2>
      <p>
        Because eStamp Pro provides access to digital services immediately
        after purchase, refunds are generally not issued for partially used
        subscription periods or simply because a customer no longer requires
        the service, except where required by applicable law.
      </p>

      <h2>Payment Provider</h2>
      <p>
        Subscription payments and refunds may be processed through the payment
        provider associated with the customer's subscription. Processing times
        after an approved refund may depend on that provider and the customer's
        financial institution.
      </p>

      <h2>How to Request Billing Assistance</h2>
      <p>
        Contact{" "}
        <a href="mailto:support@estamppro.com">
          support@estamppro.com
        </a>{" "}
        using the email address associated with your eStamp Pro account. Please
        include your organization name, if applicable, and a brief description
        of the billing issue. Do not send passwords or payment credentials by
        email.
      </p>

      <h2>Applicable Law</h2>
      <p>
        Nothing in this policy limits any refund, cancellation, or consumer
        rights that cannot be excluded under applicable law.
      </p>
    </PublicPageShell>
  );
}