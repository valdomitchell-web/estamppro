import express from "express";
import mongoose from "mongoose";
import Audit from "../models/Audit.js";
import { requireAuth } from "./mw.js";

const router = express.Router();

function isPlatformAdmin(req) {
  return ["owner", "admin", "staff"].includes(
    String(req.user?.platform_role || "").toLowerCase()
  );
}

function sinceDate(hours = 24) {
  return new Date(Date.now() - hours * 60 * 60 * 1000);
}

router.get("/system", requireAuth, async (req, res) => {
  if (!isPlatformAdmin(req)) {
    return res.status(403).json({
      ok: false,
      error: "forbidden",
    });
  }

  res.json({
    ok: true,
    system: {
      status: "online",
      uptimeSeconds: Math.floor(process.uptime()),
      nodeEnv: process.env.NODE_ENV || "development",
      nodeVersion: process.version,
      timestamp: new Date().toISOString(),
    },
  });
});

router.get("/database", requireAuth, async (req, res) => {
  if (!isPlatformAdmin(req)) {
    return res.status(403).json({
      ok: false,
      error: "forbidden",
    });
  }

  const readyState = mongoose.connection.readyState;

  const states = {
    0: "disconnected",
    1: "connected",
    2: "connecting",
    3: "disconnecting",
  };

  res.json({
    ok: readyState === 1,
    database: {
      state: states[readyState] || "unknown",
      readyState,
      host: mongoose.connection.host || null,
      name: mongoose.connection.name || null,
      timestamp: new Date().toISOString(),
    },
  });
});

router.get("/errors", requireAuth, async (req, res) => {
  if (!isPlatformAdmin(req)) {
    return res.status(403).json({
      ok: false,
      error: "forbidden",
    });
  }

  const since = sinceDate(24);

  const failedAudits = await Audit.find({
  ok: false,
  $or: [
    { timestamp: { $gte: since } },
    { createdAt: { $gte: since } },
    { created_at: { $gte: since } },
  ],
})
  .sort({
    timestamp: -1,
    createdAt: -1,
    created_at: -1,
  })
  .limit(20)
  .lean();

  res.json({
    ok: true,
    errors: {
      failedActions24h: failedAudits.length,
      items: failedAudits,
      timestamp: new Date().toISOString(),
    },
  });
});

router.get("/launch", requireAuth, async (req, res) => {
  if (!isPlatformAdmin(req)) {
    return res.status(403).json({
      ok: false,
      error: "forbidden",
    });
  }

const since = sinceDate(24);

const dateFilter = {
  $or: [
    { timestamp: { $gte: since } },
    { createdAt: { $gte: since } },
    { created_at: { $gte: since } },
  ],
};

 const failedActions24h = await Audit.countDocuments({
  ok: false,
  ...dateFilter,
});

const nonCriticalFailureFilter = {
  $or: [
    // Expected security/validation rejection.
    { action: "document.upload.rejected" },

    // Browser-extension noise such as MetaMask.
    {
      action: "system.frontend_error",
      "meta.message": { $regex: "MetaMask", $options: "i" },
    },
  ],
};

const criticalFailedActions24h = await Audit.countDocuments({
  ok: false,
  ...dateFilter,
  $nor: nonCriticalFailureFilter.$or,
});

const logins24h = await Audit.countDocuments({
  action: "auth.login",
  ...dateFilter,
});

const uploads24h = await Audit.countDocuments({
  action: "document.upload",
  ...dateFilter,
});

const stampActions24h = await Audit.countDocuments({
  action: {
    $in: [
      "stamp.apply.single",
      "stamp.apply.bulk.item",
      "stamp.create",
    ]
  },
  ...dateFilter,
});

  const dbConnected = mongoose.connection.readyState === 1;

  const criticalIssues = [];

  if (!dbConnected) {
    criticalIssues.push("Database is not connected");
  }

  if (criticalFailedActions24h > 0) {
  criticalIssues.push(
    `${criticalFailedActions24h} critical failed actions in the last 24 hours`
  );
}

const readyForBeta =
  dbConnected &&
  criticalFailedActions24h === 0;

  res.json({
    ok: true,
    launch: {
      readyForBeta,
      status: readyForBeta ? "ready" : "not_ready",
      database: dbConnected ? "connected" : "not_connected",
      failedActions24h,
      criticalFailedActions24h,
      logins24h,
      uploads24h,
      stampActions24h,
      criticalIssues,
      timestamp: new Date().toISOString(),
    },
  });
});

export default router;