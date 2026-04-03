Focused hotfix patch for four issues:

1. Delivery cards showing Invalid Date
2. Resend failing when a stored delivery has no html/text snapshot
3. Analytics counts staying at zero despite sends/opens/clicks
4. Analytics refresh surfacing the wrong stale page error

Files included:
- server/src/routes/verify.js
- server/src/routes/email_analytics.js
- server/src/routes/resend_webhook.js
- server/src/lib/emailAnalytics.js
- web/src/App.jsx
- web/src/EmailAnalyticsPanel.jsx

Merge into your current branch, then redeploy API and web.
