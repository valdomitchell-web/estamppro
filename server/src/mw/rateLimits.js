import rateLimit, {
  ipKeyGenerator,
} from "express-rate-limit";

function normalizeIp(req) {
  const ip =
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";

  if (ip === "unknown") {
    return ip;
  }

  return ipKeyGenerator(ip);
}

function authenticatedKey(req) {
  const userId =
    req.user?.uid ||
    req.user?._id ||
    req.user?.id ||
    null;

  const orgId =
    req.user?.org_id ||
    req.user?.orgId ||
    null;

  if (userId) {
    return `user:${String(userId)}`;
  }

  if (orgId) {
    return `org:${String(orgId)}`;
  }

  return `ip:${normalizeIp(req)}`;
}

function apiKeyRequestKey(req) {
  const apiKeyId =
    req.api?.key_id ||
    req.api?.keyId ||
    req.api?._id ||
    req.api?.id ||
    null;

  const orgId =
    req.api?.org_id ||
    req.api?.orgId ||
    req.api?.organizationId ||
    null;

  if (apiKeyId) {
    return `api-key:${String(apiKeyId)}`;
  }

  if (orgId) {
    return `api-org:${String(orgId)}`;
  }

  return `ip:${normalizeIp(req)}`;
}

function makeLimiter({
  windowMs,
  max,
  keyGenerator,
  error,
  skipSuccessfulRequests = false,
}) {
  return rateLimit({
    windowMs,
    max,
    keyGenerator,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    handler(_req, res) {
      return res.status(429).json({
        ok: false,
        error,
      });
    },
  });
}

/**
 * Single-document stamping and password attempts.
 * 30 requests per authenticated user per hour.
 */
export const stampApplyLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  keyGenerator: authenticatedKey,
  error: "too_many_stamp_attempts",
});

/**
 * Stamp preview also parses and redraws a PDF and checks
 * the stamp password, so it needs separate protection.
 */
export const stampPreviewLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 60,
  keyGenerator: authenticatedKey,
  error: "too_many_stamp_preview_attempts",
});

/**
 * Bulk stamping and ZIP generation are especially expensive.
 */
export const bulkStampLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: authenticatedKey,
  error: "too_many_bulk_stamp_requests",
});

/**
 * PDF uploads.
 */
export const documentUploadLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  keyGenerator: authenticatedKey,
  error: "too_many_document_uploads",
});

/**
 * Authenticated PDF verification uploads.
 */
export const documentVerifyLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 60,
  keyGenerator: authenticatedKey,
  error: "too_many_document_verification_requests",
});

/**
 * Verification API requests using API keys.
 */
export const apiVerifyLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 300,
  keyGenerator: apiKeyRequestKey,
  error: "too_many_api_verification_requests",
});

/**
 * Public verification pages and certificate generation.
 */
export const publicVerifyLimiter = makeLimiter({
  windowMs: 15 * 60 * 1000,
  max: 120,
  keyGenerator: (req) => `ip:${normalizeIp(req)}`,
  error: "too_many_public_verification_requests",
});

/**
 * Verification emails can consume provider quota.
 */
export const verificationEmailLimiter = makeLimiter({
  windowMs: 60 * 60 * 1000,
  max: 30,
  keyGenerator: authenticatedKey,
  error: "too_many_verification_email_requests",
});