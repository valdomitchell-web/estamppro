# eStamp Pro open + click tracking patch

## Add these backend mounts
- Mount `routes/resend_webhook.js`
- Mount `routes/email_analytics.js`
- Layer `routes/verify_public.js` click tracking before your existing verify public handlers, or merge the helper into the existing file.

## Webhook endpoint
POST /webhooks/resend

Enable Resend events:
- email.sent
- email.delivered
- email.opened
- email.bounced
- email.complained

## Frontend
Render `web/src/EmailAnalyticsPanel.jsx` somewhere in your dashboard and pass your API base if needed.
