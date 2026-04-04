import express from "express";
import { requireAuth } from "./mw.js";
import { loadAnalyticsPayload } from "./email_analytics.js";

const router = express.Router();

function writeEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

router.get("/verify/share/analytics/stream", requireAuth, async (req, res) => {
  const days = Number(req.query.days || 30);
  const heartbeatMs = Math.max(5000, Number(process.env.ANALYTICS_STREAM_HEARTBEAT_MS || 30000));

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  if (typeof res.flushHeaders === "function") {
    res.flushHeaders();
  }

  const sendSnapshot = async () => {
    try {
      const payload = await loadAnalyticsPayload(req.user.orgId, days);
      writeEvent(res, "snapshot", payload);
    } catch {
      writeEvent(res, "error", { error: "Failed to stream analytics" });
    }
  };

  await sendSnapshot();

  const heartbeat = setInterval(() => {
    writeEvent(res, "heartbeat", { ts: Date.now() });
  }, heartbeatMs);

  const poll = setInterval(async () => {
    await sendSnapshot();
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    clearInterval(poll);
    try {
      res.end();
    } catch {}
  });
});

export default router;