# eStamp Pro — Direct full-file webhook + analytics patch

This bundle is a direct full-file patch for your current repo layout.

## Files included
- `server/src/index.js`
- `server/src/models/EmailDelivery.js`
- `server/src/lib/emailAnalytics.js`
- `server/src/routes/resend_webhook.js`
- `server/src/routes/email_analytics.js`
- `server/.env.example`
- `web/src/EmailAnalyticsPanel.jsx`

## What it does
- receives Resend webhook events at `POST /webhooks/resend`
- updates delivery records to `sent`, `delivered`, `opened`, `bounced`, or `complained`
- exposes analytics at `GET /verify/share/analytics`
- exposes recent delivery history at `GET /verify/share/deliveries`
- includes a frontend panel component you can drop into `App.jsx`

## Required setup
Add to Render:
- `RESEND_WEBHOOK_SECRET=whsec_...`
- `RESEND_API_KEY=re_...`
- `MAIL_FROM=verify@yourdomain.com`
- `WEB_URL=https://your-web-service.onrender.com`
- `API_URL=https://your-api-service.onrender.com`

## App.jsx integration
Import and render:
```jsx
import EmailAnalyticsPanel from "./EmailAnalyticsPanel.jsx";

<EmailAnalyticsPanel />
```

## Resend webhook
Create the webhook in Resend pointing to:
`https://your-api-service.onrender.com/webhooks/resend`

Enable:
- email.sent
- email.delivered
- email.opened
- email.bounced
- email.complained
