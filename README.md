# Open-count correction hotfix

This hotfix fixes the case where:
- top-level **Opened** counts are correct
- but per-document **Total opens** shows `0`

## Files included
- `server/src/lib/emailAnalytics.js`
- `server/src/routes/resend_webhook.js`

## What to merge

### 1) In `emailAnalytics.js`
Use `events[]` as the fallback source of truth for:
- `total_opens`
- `total_clicks`

Included helper:
- `getEventCount(delivery, type)`
- `applyDeliveryToDocumentStats(doc, delivery)`

### 2) In `resend_webhook.js`
For `email.opened` and click-tracking events, append an event record to `delivery.events[]` every time.

Included helper:
- `appendTrackingEvent(delivery, type, payload)`

## Expected result after deploy
- `Opened` still reflects how many deliveries/documents were opened
- `Total opens` now reflects the actual number of open events
- repeated opens increase the total count
