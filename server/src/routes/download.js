import express from "express";
import path from "path";
import fs from "fs";
import { requireAuth } from "./mw.js";

const router = express.Router();

const DOWNLOAD_TTL_MS = 15 * 60 * 1000;

function sameId(a, b) {
  return String(a || "") === String(b || "");
}

function removeDownload(map, id, item) {
  map.delete(id);

  const relPath =
    typeof item === "string"
      ? item
      : item?.path;

  if (!relPath) return;

  const absPath = path.resolve(
    process.cwd(),
    relPath
  );

  const uploadsRoot = path.resolve(
    process.cwd(),
    "uploads"
  );

  if (
    absPath !== uploadsRoot &&
    !absPath.startsWith(`${uploadsRoot}${path.sep}`)
  ) {
    console.error(
      "[DOWNLOAD CLEANUP] Refused path outside uploads:",
      absPath
    );
    return;
  }

  fs.promises.unlink(absPath).catch((error) => {
    if (error?.code !== "ENOENT") {
      console.error(
        "[DOWNLOAD CLEANUP] Failed:",
        error
      );
    }
  });
}

router.get("/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const downloads =
      globalThis.__downloads || new Map();

    const item = downloads.get(id);

    if (!item || typeof item === "string") {
      return res.status(404).json({
        ok: false,
        error: "download_not_found",
      });
    }

    const requestOrgId =
      req.user?.org_id ||
      req.user?.orgId ||
      null;

    if (
      !requestOrgId ||
      !sameId(item.org_id, requestOrgId)
    ) {
      return res.status(404).json({
        ok: false,
        error: "download_not_found",
      });
    }

    const createdAt = Number(item.created_at || 0);

    if (
      !createdAt ||
      Date.now() - createdAt > DOWNLOAD_TTL_MS
    ) {
      removeDownload(downloads, id, item);

      return res.status(410).json({
        ok: false,
        error: "download_expired",
      });
    }

    const absPath = path.resolve(
      process.cwd(),
      item.path
    );

    const uploadsRoot = path.resolve(
      process.cwd(),
      "uploads"
    );

    if (
      absPath !== uploadsRoot &&
      !absPath.startsWith(`${uploadsRoot}${path.sep}`)
    ) {
      console.error(
        "[DOWNLOAD] Refused path outside uploads:",
        absPath
      );

      downloads.delete(id);

      return res.status(404).json({
        ok: false,
        error: "download_not_found",
      });
    }

    if (!fs.existsSync(absPath)) {
      downloads.delete(id);

      return res.status(404).json({
        ok: false,
        error: "download_not_found",
      });
    }

    res.setHeader(
      "Cache-Control",
      "private, no-store, max-age=0"
    );

    res.setHeader(
      "X-Content-Type-Options",
      "nosniff"
    );

    const filename =
      item.filename ||
      path.basename(absPath);

    return res.download(
      absPath,
      filename,
      (error) => {
        if (error) {
          if (!res.headersSent) {
            res.status(500).json({
              ok: false,
              error: "download_failed",
            });
          }

          return;
        }

        removeDownload(downloads, id, item);
      }
    );
  } catch (error) {
    console.error("[DOWNLOAD] error:", error);

    return res.status(500).json({
      ok: false,
      error: "download_failed",
    });
  }
});

export default router;
