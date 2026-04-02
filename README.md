# Open + click tracking direct integration patch

This patch is designed to layer onto the current eStamp Pro branch without replacing your large dashboard file.

## Backend files added
- `server/src/models/EmailDelivery.js`
- `server/src/lib/emailAnalytics.js`
- `server/src/routes/resend_webhook.js`
- `server/src/routes/email_analytics.js`
- `server/src/routes/verify_public_tracking.js`

## Frontend file added
- `web/src/EmailAnalyticsPanel.jsx`

## Required backend mounts
In `server/src/index.js` add these imports:

```js
import resendWebhookRoutes from "./routes/resend_webhook.js";
import emailAnalyticsRoutes from "./routes/email_analytics.js";
import verifyPublicTrackingRoutes from "./routes/verify_public_tracking.js";
```

Then mount them **before** your existing `verify_public` route:

```js
app.use("/webhooks", resendWebhookRoutes);
app.use("/", emailAnalyticsRoutes);
app.use("/verify/public", verifyPublicTrackingRoutes);
app.use("/verify/public", verifyPublicRoutes);
```

That order matters. The tracking wrapper should run before your existing public verification/certificate handlers.

## Frontend integration
In your dashboard file, add:

```js
import EmailAnalyticsPanel from "./EmailAnalyticsPanel.jsx";
```

Then render it somewhere below your email delivery section:

```jsx
<EmailAnalyticsPanel />
```

## Resend webhook
Point Resend to:

```text
https://your-api-service.onrender.com/webhooks/resend
```

Enable:
- `email.sent`
- `email.delivered`
- `email.opened`
- `email.bounced`
- `email.complained`
