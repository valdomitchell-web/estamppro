import React, { useEffect, useMemo, useRef, useState } from "react";
import api from "./api";
import StampDesigner from "./StampDesigner.jsx";
import { Document as PdfDocument, Page, pdfjs } from "react-pdf";
import EmailAnalyticsPanel from "./EmailAnalyticsPanel.jsx";
import "react-pdf/dist/Page/AnnotationLayer.css";
import "react-pdf/dist/Page/TextLayer.css";
import AnalyticsReportsSettings from "./AnalyticsReportsSettings";
import AnalyticsReportsHistory from "./AnalyticsReportsHistory";
import UpgradeModal from "./UpgradeModal";

pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

export default function App() {
  const [email, setEmail] = useState("valdomitchell@gmail.com");
  const [password, setPassword] = useState("");
  const [me, setMe] = useState(null);
  const [err, setErr] = useState("");
  const [success, setSuccess] = useState("");
  const [upgradeHint, setUpgradeHint] = useState(null);

  const [upgradeModalOpen, setUpgradeModalOpen] = useState(false);
  const [upgradeFeatureKey, setUpgradeFeatureKey] = useState("pro_branding");

  const [file, setFile] = useState(null);
  const [lastDocId, setLastDocId] = useState(null);

  const [bulkFiles, setBulkFiles] = useState([]);
  const [bulkDocumentIds, setBulkDocumentIds] = useState([]);
  const [bulkResults, setBulkResults] = useState([]);

  const [previewPdfFile, setPreviewPdfFile] = useState(null);
  const [previewPageCount, setPreviewPageCount] = useState(0);
  const [previewLoaded, setPreviewLoaded] = useState(false);
  const [browserPreviewBlocked, setBrowserPreviewBlocked] = useState(false);

  const [stamps, setStamps] = useState([]);
  const [selectedStamp, setSelectedStamp] = useState("");
  const [stampPassword, setStampPassword] = useState("");

  const [stampPage, setStampPage] = useState(0);
  const [stampX, setStampX] = useState(50);
  const [stampY, setStampY] = useState(50);
  const [stampScale, setStampScale] = useState(1);
  const [stampOpacity, setStampOpacity] = useState(1);

  const [dragX, setDragX] = useState(50);
  const [dragY, setDragY] = useState(50);

  const [applyResult, setApplyResult] = useState(null);

  const [verifyFile, setVerifyFile] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);

  const [audit, setAudit] = useState([]);

  const [orgInfo, setOrgInfo] = useState(null);
  const [billingStatus, setBillingStatus] = useState(null);

  const [team, setTeam] = useState([]);
  const [teamBusyId, setTeamBusyId] = useState("");
  const [orgName, setOrgName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("user");
  
  const [previewRenderWidth, setPreviewRenderWidth] = useState(520);
  const [brandingForm, setBrandingForm] = useState({
    logo_url: "",
    primary_color: "#1d4ed8",
    accent_color: "#0f172a",
    stamp_label: "Official Organization Stamp",
    email_footer: "",
    watermark_text: "",
    verification_tagline: "",
    email_header_text: "",
    support_email: "",
    website_url: "",
    from_name: "",
    reply_to: "",
  });

  const [apiKeys, setApiKeys] = useState([]);
  const [newKey, setNewKey] = useState(null);
  const [newKeyName, setNewKeyName] = useState("Default Key");
  const [activeTab, setActiveTab] = useState("stamp");

const [selectedAuditForShare, setSelectedAuditForShare] = useState("");
const [shareTemplate, setShareTemplate] = useState(null);
const [shareSending, setShareSending] = useState(false);
const [deliveries, setDeliveries] = useState([]);
const [deliveryLoading, setDeliveryLoading] = useState(false);
const [resendingDeliveryId, setResendingDeliveryId] = useState("");
const [shareForm, setShareForm] = useState({
  to: "",
  cc: "",
  bcc: "",
  subject: "",
  note: "",
});
const [previewImageMeta, setPreviewImageMeta] = useState({
  naturalWidth: 0,
  naturalHeight: 0,
});

const [exactPreviewUrl, setExactPreviewUrl] = useState("");
const [exactPreviewLoading, setExactPreviewLoading] = useState(false);

  const pageRef = useRef(null);
  const boxRef = useRef(null);
  const previewFrameRef = useRef(null);

  const billingQuery =
    new URLSearchParams(window.location.search).get("billing") || "";

  const openUpgradeModal = (featureKey) => {
    setUpgradeFeatureKey(featureKey || "pro_branding");
    setUpgradeModalOpen(true);
  };

  const loadExactStampedPreview = async () => {
  if (!selectedStamp || !previewDocumentId || !stampPassword) return;

  setExactPreviewLoading(true);
  try {
    const response = await api.post(
      `/stamps/${selectedStamp}/preview-page`,
      {
        documentId: previewDocumentId,
        page: Number(stampPage) || 0,
        x: Number(stampX) || 0,
        y: Number(stampY) || 0,
        scale: Number(stampScale) || 1,
        opacity: Number(stampOpacity) || 1,
        password: stampPassword,
      },
      { responseType: "blob" }
    );

    console.log("preview-page status", response.status, response.data);

    const url = URL.createObjectURL(
      new Blob([response.data], { type: "application/pdf" })
    );

    setExactPreviewUrl((old) => {
      if (old) URL.revokeObjectURL(old);
      return url;
    });
  } catch (e) {
  setExactPreviewUrl("");

  let msg = e?.message || "Failed to load exact preview";

  try {
    if (e?.response?.data instanceof Blob) {
      const text = await e.response.data.text();
      const json = JSON.parse(text);
      msg = json?.detail || json?.error || msg;
    } else {
      msg =
        e?.response?.data?.detail ||
        e?.response?.data?.error ||
        e?.message ||
        msg;
    }
  } catch {}

  console.error("preview-page failed", e?.response?.status, msg);
  setErr(msg);
} finally {
  setExactPreviewLoading(false);
}
};

  const closeUpgradeModal = () => {
    setUpgradeModalOpen(false);
  };

  const clearErr = () => {
  setErr("");
  setSuccess("");
  setUpgradeHint(null);
};

  const showErr = (e) => {
  console.error(e);
  const payload = e?.response?.data || {};
  const raw =
    payload?.userMessage ||
    payload?.detail ||
    payload?.message ||
    payload?.error ||
    e?.message ||
    "Unknown error";

  const msg =
    String(raw).toLowerCase() === "failed to fetch"
      ? "Download could not be fetched directly. Opening file in browser instead."
      : raw;

  if (["upgrade_required", "limit_reached"].includes(payload?.error)) {
    setUpgradeHint(payload);
  }

  setSuccess("");
  setErr(String(msg));
};
const showSuccess = (msg) => {
  setErr("");
  setUpgradeHint(null);
  setSuccess(String(msg || ""));
};
const fmtDeliveryDate = (row) => {
  const raw =
    row?.createdAt ||
    row?.created_at ||
    row?.sent_at ||
    row?.queued_at ||
    row?.updatedAt ||
    row?.updated_at ||
    null;

  if (!raw) return "—";

  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? "—" : dt.toLocaleString();
};
  const fmtDate = (value) => {
    if (!value) return "—";
    const dt = new Date(value);
    return Number.isNaN(dt.getTime()) ? "—" : dt.toLocaleString();
  };

  const selectedStampObj = useMemo(
    () =>
      stamps.find((s) => String(s._id || s.id) === String(selectedStamp)) ||
      null,
    [stamps, selectedStamp]
  );

  const previewDocumentId =
  lastDocId || bulkDocumentIds?.[0]?.id || bulkDocumentIds?.[0] || null;

  const baseStampWidth = Number(selectedStampObj?.width || 160);
  const baseStampHeight = Number(selectedStampObj?.height || 80);

  const previewStampSrc =
  selectedStampObj?.image_url ||
  selectedStampObj?.imageUrl ||
  "";

const hasRealStampPreview = !!previewStampSrc;

const realStampAspect =
  previewImageMeta.naturalWidth > 0 && previewImageMeta.naturalHeight > 0
    ? previewImageMeta.naturalWidth / previewImageMeta.naturalHeight
    : baseStampWidth > 0 && baseStampHeight > 0
    ? baseStampWidth / baseStampHeight
    : 1;

  const pdfPageWidth = 612;
  const pdfPageHeight = 792;
  const maxWidth = pdfPageWidth * 0.28;
  const maxHeight = pdfPageHeight * 0.18;

  let appliedScale = Number(stampScale) || 1;
  if (
    baseStampWidth * appliedScale > maxWidth ||
    baseStampHeight * appliedScale > maxHeight
  ) {
    const fx = maxWidth / baseStampWidth;
    const fy = maxHeight / baseStampHeight;
    appliedScale = Math.min(appliedScale, fx, fy);
  }

  const previewBaseWidth = Math.max(36, Math.round(baseStampWidth * appliedScale));

const previewBaseHeight = Math.max(
  22,
  Math.round(
    realStampAspect > 0
      ? previewBaseWidth / realStampAspect
      : baseStampHeight * appliedScale
  )
);

const PDF_WIDTH = 612;
const PDF_HEIGHT = 792;

const scaleFactor = previewRenderWidth / PDF_WIDTH;

const effectivePreviewBoxWidth = baseStampWidth * appliedScale * scaleFactor;
const effectivePreviewBoxHeight = baseStampHeight * appliedScale * scaleFactor;
const previewBoxWidth = previewBaseWidth;
const previewBoxHeight = previewBaseHeight;

  const clampPreviewToBounds = (x, y, pageWidth, pageHeight) => {
    const maxX = Math.max(0, pageWidth - effectivePreviewBoxWidth);
    const maxY = Math.max(0, pageHeight - effectivePreviewBoxHeight);
    return {
      x: Math.min(Math.max(0, x), maxX),
      y: Math.min(Math.max(0, y), maxY),
    };
  };

  const syncPreviewFromPdfCoords = () => {
    if (!pageRef.current) return;
    const pageRect = pageRef.current.getBoundingClientRect();
    if (!pageRect.width || !pageRect.height) return;

    const scaleX = pageRect.width / pdfPageWidth;
    const scaleY = pageRect.height / pdfPageHeight;

    const rawX = (Number(stampX) || 0) * scaleX;
    const rawY =
  pageRect.height - (Number(stampY) || 0) * scaleY - effectivePreviewBoxHeight;

    const clamped = clampPreviewToBounds(
      rawX,
      rawY,
      pageRect.width,
      pageRect.height
    );
    setDragX(clamped.x);
    setDragY(clamped.y);
  };

  const downloadBlobFile = (blob, filename) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const smartDownloadFromUrl = async (url, filename) => {
    try {
      const target = new URL(url, window.location.origin);

      if (
        target.origin === window.location.origin ||
        url.startsWith(api.defaults.baseURL)
      ) {
        const res = await fetch(url, { credentials: "include" });
        if (!res.ok) throw new Error(`Download failed: ${res.status}`);
        const blob = await res.blob();
        downloadBlobFile(blob, filename);
        return;
      }

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.target = "_blank";
      a.rel = "noreferrer";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  };

  const formatUsage = (used, limit, unit = "") => {
    const suffix = unit ? ` ${unit}` : "";
    const left = `${used}${suffix}`;
    if (limit === null || limit === undefined) return `${left} / Unlimited`;
    return `${left} / ${limit}${suffix}`;
  };

  const getUsageStatus = (pct = 0) => {
    const safePct = Number(pct || 0);

    if (safePct >= 100) {
      return {
        tone: "limit",
        label: "Limit reached",
        color: "#b91c1c",
        bg: "#fef2f2",
        border: "#fecaca",
      };
    }

    if (safePct >= 95) {
      return {
        tone: "critical",
        label: "Almost full",
        color: "#c2410c",
        bg: "#fff7ed",
        border: "#fdba74",
      };
    }

    if (safePct >= 80) {
      return {
        tone: "warning",
        label: "Approaching limit",
        color: "#a16207",
        bg: "#fffbeb",
        border: "#fde68a",
      };
    }

    return {
      tone: "ok",
      label: "Healthy",
      color: "#1d4ed8",
      bg: "#eff6ff",
      border: "#bfdbfe",
    };
  };

  const getUpgradeTargetPlan = () => {
    if (currentPlan === "free") return "pro";
    if (currentPlan === "pro") return "business";
    return "business";
  };

  const getUpgradeFeatureKeyForUsage = (key) => {
    if (key === "storageUsedMB") return "business_storage";
    if (key === "stampsThisMonth") return "pro_limits";
    if (key === "documentsThisMonth") return "pro_limits";
    return "pro_branding";
  };

  const tabs = [
  { key: "stamp", label: "Stamping" },
  { key: "org", label: "Organization" },
  { key: "branding", label: "Branding" },
  { key: "email", label: "Email" },
  { key: "team", label: "Team & API" },
  { key: "analytics", label: "Analytics" },
  { key: "audit", label: "Verify & Audit" },
];

const tabButton = (key) => ({
  padding: "10px 16px",
  borderRadius: 999,
  border: activeTab === key ? "1px solid #1d4ed8" : "1px solid #cbd5e1",
  background: activeTab === key ? "#1d4ed8" : "#fff",
  color: activeTab === key ? "#fff" : "#1d4ed8",
  fontWeight: 800,
  cursor: "pointer",
});

  const getPlanCardButton = (planKey) => {
    if (planKey === currentPlan) {
  return null;
}

    if (currentPlan === "free" && planKey === "pro") {
      return {
        label: "Upgrade to Pro",
        disabled: false,
        style: buttonSecondary,
      };
    }

    if (currentPlan === "free" && planKey === "business") {
      return {
        label: "Upgrade to Business",
        disabled: false,
        style: buttonStyle,
      };
    }

    if (currentPlan === "pro" && planKey === "business") {
      return {
        label: "Upgrade to Business",
        disabled: false,
        style: buttonStyle,
      };
    }

    if (currentPlan === "business" && planKey !== "business") {
  return null;
}

    return {
      label: `Choose ${planKey}`,
      disabled: false,
      style: buttonSecondary,
    };
  };

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`${api.defaults.baseURL}/health`, {
          credentials: "omit",
          cache: "no-store",
        });
        if (!r.ok) throw new Error(`API health ${r.status}`);
      } catch (e) {
        console.error(e);
        setErr("API not reachable. Check backend and CORS.");
      }
    })();

    (async () => {
      try {
        const r = await api.get("/auth/me").catch(() => null);
        if (r?.data?.user) setMe(r.data.user);
      } catch {}
    })();
  }, []);

  useEffect(() => {
  if (!selectedStamp || !previewDocumentId || !stampPassword) {
    setExactPreviewLoading(false);
    setExactPreviewUrl("");
    return;
  }

  const t = setTimeout(() => {
    loadExactStampedPreview();
  }, 500);

  return () => clearTimeout(t);
}, [
  selectedStamp,
  previewDocumentId,
  stampPassword,
  stampPage,
  stampX,
  stampY,
  stampScale,
  stampOpacity,
]);

useEffect(() => {
  const updatePreviewWidth = () => {
    if (!previewFrameRef.current) return;
    const width = Math.max(320, Math.floor(previewFrameRef.current.clientWidth));
    setPreviewRenderWidth(Math.min(520, width));
  };

  updatePreviewWidth();
  window.addEventListener("resize", updatePreviewWidth);
  return () => window.removeEventListener("resize", updatePreviewWidth);
}, []);

useEffect(() => {
  return () => {
    if (exactPreviewUrl) URL.revokeObjectURL(exactPreviewUrl);
  };
}, [exactPreviewUrl]);

  useEffect(() => {
    if (!me) return;
    loadOrg();
    loadTeam();
    loadApiKeys();
    loadStamps();
    loadBillingStatus();
    loadAudit();
  }, [me]);

useEffect(() => {
  if (!selectedStamp) return;

  const saved = loadSavedStampPlacement(selectedStamp);
  if (!saved) return;

 setStampPage(saved.page);
 setStampX(saved.x);
 setStampY(saved.y);
 setStampScale(saved.scale);
  setStampOpacity(saved.opacity);
}, [selectedStamp]);

useEffect(() => {
  if (!selectedStamp) return;

  saveStampPlacement(selectedStamp, {
    page: stampPage,
    x: stampX,
    y: stampY,
    scale: stampScale,
    opacity: stampOpacity,
  });
}, [selectedStamp, stampPage, stampX, stampY, stampScale, stampOpacity]);

 // useEffect(() => {
  //if (!previewLoaded || !selectedStampObj) return;
  //placeStampSmart();
//}, [previewLoaded, selectedStamp]);

  useEffect(() => {
    if (!orgInfo?.branding) return;

    setBrandingForm({
      logo_url: orgInfo.branding.logo_url || "",
      primary_color: orgInfo.branding.primary_color || "#1d4ed8",
      accent_color: orgInfo.branding.accent_color || "#0f172a",
      stamp_label:
        orgInfo.branding.stamp_label || "Official Organization Stamp",
      email_footer: orgInfo.branding.email_footer || "",
      watermark_text: orgInfo.branding.watermark_text || "",
      verification_tagline: orgInfo.branding.verification_tagline || "",
      email_header_text: orgInfo.branding.email_header_text || "",
      support_email: orgInfo.branding.support_email || "",
      website_url: orgInfo.branding.website_url || "",
      from_name:
        orgInfo.emailSettings?.from_name ||
        orgInfo.branding.stamp_label ||
        orgInfo.name ||
        "",
      reply_to: orgInfo.emailSettings?.reply_to || me?.email || "",
    });
  }, [orgInfo?.branding, me?.email]);

  useEffect(() => {
    if (!file && bulkFiles.length > 0) {
      setBrowserPreviewBlocked(false);
      setPreviewPdfFile(bulkFiles[0]);
      setPreviewLoaded(false);
    }
  }, [bulkFiles, file]);

  useEffect(() => {
    if (!previewLoaded) return;
    syncPreviewFromPdfCoords();
  }, [
    previewLoaded,
    selectedStamp,
    stampScale,
    stampX,
    stampY,
    baseStampWidth,
    baseStampHeight,
  ]);

  useEffect(() => {
    if (!billingQuery) return;

    if (billingQuery === "success") {
      setErr(
        "Billing checkout completed. Your plan will update as soon as Stripe confirms the subscription."
      );
      loadBillingStatus();
      loadOrg();
    } else if (billingQuery === "cancel") {
      setErr("Billing checkout was canceled.");
    } else if (billingQuery === "portal_return") {
      setErr("Returned from billing portal.");
      loadBillingStatus();
      loadOrg();
    }
  }, [billingQuery]);

  function clampToRange(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

const getCandidatePlacements = () => {
  if (!pageRef.current) return [];

  const rect = pageRef.current.getBoundingClientRect();
  const margin = 16;
  const boxW = effectivePreviewBoxWidth;
  const boxH = effectivePreviewBoxHeight;

  return [
    {
      key: "top-right",
      x: rect.width - boxW - margin,
      y: margin,
      score: 95,
    },
    {
      key: "bottom-right",
      x: rect.width - boxW - margin,
      y: rect.height - boxH - margin,
      score: 100,
    },
    {
      key: "top-left",
      x: margin,
      y: margin,
      score: 80,
    },
    {
      key: "bottom-left",
      x: margin,
      y: rect.height - boxH - margin,
      score: 85,
    },
    {
      key: "center-right",
      x: rect.width - boxW - margin,
      y: rect.height / 2 - boxH / 2,
      score: 60,
    },
    {
      key: "center-left",
      x: margin,
      y: rect.height / 2 - boxH / 2,
      score: 70,
    },
  ].map((item) => ({
    ...item,
    x: clampToRange(item.x, 0, rect.width - boxW),
    y: clampToRange(item.y, 0, rect.height - boxH),
  }));
};

const placeStampSmart = () => {
  if (!pageRef.current) return;

  const candidates = getCandidatePlacements();
  if (!candidates.length) return;

  const previewTemplate = pickPreviewTemplate(selectedStampObj);

  let ranked = [...candidates];

  if (
  previewTemplate === "businessRect" ||
  previewTemplate === "officialRect" ||
  previewTemplate === "genericWideRect" ||
  previewTemplate === "genericTallRect"
) {
  ranked.sort((a, b) => {
    const rectPriority = {
      "top-right": 6,
      "bottom-right": 5,
      "top-left": 4,
      "bottom-left": 3,
      "center-right": 2,
      "center-left": 1,
    };
    return rectPriority[b.key] - rectPriority[a.key];
  });
} else if (
  previewTemplate === "officialCircle" ||
  previewTemplate === "genericCircle"
) {
  ranked.sort((a, b) => {
    const circlePriority = {
      "bottom-right": 6,
      "top-right": 5,
      "bottom-left": 4,
      "top-left": 3,
      "center-right": 2,
      "center-left": 1,
    };
    return circlePriority[b.key] - circlePriority[a.key];
  });
} else if (
    previewTemplate === "officialCircle" ||
    previewTemplate === "genericCircle"
  ) {
    ranked.sort((a, b) => {
      const circlePriority = {
        "bottom-right": 5,
        "top-right": 4,
        "bottom-left": 3,
        "top-left": 2,
        "center-right": 1,
      };
      return circlePriority[b.key] - circlePriority[a.key];
    });
  }

  const best = ranked[0];
  if (!best) return;

  const rect = pageRef.current.getBoundingClientRect();
  const boxW = effectivePreviewBoxWidth;
  const boxH = effectivePreviewBoxHeight;

  setDragX(best.x);
  setDragY(best.y);

  const scaleX = pdfPageWidth / rect.width;
  const scaleY = pdfPageHeight / rect.height;

  const pdfX = Math.round(best.x * scaleX);
  const pdfY = Math.round((rect.height - best.y - boxH) * scaleY);

  setStampX(pdfX);
  setStampY(pdfY);
};

const placeStampPreset = (preset) => {
  if (!pageRef.current) return;

  const rect = pageRef.current.getBoundingClientRect();
  const margin = 16;

  const boxW = effectivePreviewBoxWidth;
  const boxH = effectivePreviewBoxHeight;

  let nextX = dragX;
  let nextY = dragY;

  switch (preset) {
    case "top-left":
      nextX = margin;
      nextY = margin;
      break;

    case "top-right":
      nextX = rect.width - boxW - margin;
      nextY = margin;
      break;

    case "bottom-left":
      nextX = margin;
      nextY = rect.height - boxH - margin;
      break;

    case "bottom-right":
      nextX = rect.width - boxW - margin;
      nextY = rect.height - boxH - margin;
      break;

    case "center-right":
      nextX = rect.width - boxW - margin;
      nextY = rect.height / 2 - boxH / 2;
      break;

    case "center-left":
      nextX = margin;
      nextY = rect.height / 2 - boxH / 2;
      break;

    default:
      return;
  }

  nextX = clampToRange(nextX, 0, rect.width - boxW);
  nextY = clampToRange(nextY, 0, rect.height - boxH);

  setDragX(nextX);
  setDragY(nextY);

  const scaleX = pdfPageWidth / rect.width;
  const scaleY = pdfPageHeight / rect.height;

  const pdfX = Math.round(nextX * scaleX);
  const pdfY = Math.round((rect.height - nextY - boxH) * scaleY);

  setStampX(pdfX);
  setStampY(pdfY);
};

  const handlePreviewPointerDown = (e) => {
  if (!pageRef.current || !boxRef.current) return;

  e.preventDefault();
  e.stopPropagation();

  const pageRect = pageRef.current.getBoundingClientRect();
  const boxRect = boxRef.current.getBoundingClientRect();

  const startClientX = e.clientX;
  const startClientY = e.clientY;

  const offsetX = startClientX - boxRect.left;
  const offsetY = startClientY - boxRect.top;

  const onMove = (ev) => {
    ev.preventDefault();

    const clientX = ev.clientX;
    const clientY = ev.clientY;

    let x = clientX - pageRect.left - offsetX;
    let y = clientY - pageRect.top - offsetY;

    const clamped = clampPreviewToBounds(
      x,
      y,
      pageRect.width,
      pageRect.height
    );

    x = clamped.x;
    y = clamped.y;

    setDragX(x);
    setDragY(y);

    const scaleX = pdfPageWidth / pageRect.width;
    const scaleY = pdfPageHeight / pageRect.height;

    const pdfX = Math.round(x * scaleX);
    const pdfY = Math.round(
  (pageRect.height - y - effectivePreviewBoxHeight) * scaleY
);

    setStampX(pdfX);
    setStampY(pdfY);
  };

  const onUp = () => {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
  };

  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp);
};

  const register = async () => {
    clearErr();
    try {
      const r = await api.post("/auth/register", { email, password });
      if (r.data?.token) localStorage.setItem("access_token", r.data.token);
      setMe(r.data?.user || null);
    } catch (e) {
      showErr(e);
    }
  };

  const login = async () => {
    clearErr();
    try {
      const r = await api.post("/auth/login", { email, password });
      if (r.data?.token) localStorage.setItem("access_token", r.data.token);
      setMe(r.data?.user || null);
    } catch (e) {
      showErr(e);
    }
  };

  const logout = async () => {
    clearErr();
    try {
      await api.post("/auth/logout");
    } catch {}
    localStorage.removeItem("access_token");
    localStorage.removeItem("token");
    setMe(null);
    setOrgInfo(null);
    setTeam([]);
    setApiKeys([]);
    setBillingStatus(null);
    setAudit([]);
  };

  const upgradePlan = async (plan = "pro") => {
    clearErr();
    try {
      const r = await api.post("/billing/checkout", { plan });
      if (r?.data?.url) {
        window.location.href = r.data.url;
      } else {
        throw new Error("No checkout URL returned");
      }
    } catch (e) {
      showErr(e);
    }
  };

  const loadBillingStatus = async () => {
    try {
      const r = await api.get("/billing/status");
      setBillingStatus(r.data?.billing || null);
    } catch (e) {
      console.warn(
        "billing status load failed",
        e?.response?.data || e?.message
      );
    }
  };

  const openBillingPortal = async () => {
    clearErr();
    try {
      const r = await api.post("/billing/portal");
      if (r?.data?.url) {
        window.location.href = r.data.url;
      } else {
        throw new Error("No billing portal URL returned");
      }
    } catch (e) {
      showErr(e);
    }
  };

  const loadStamps = async () => {
  clearErr();
  try {
    const r = await api.get("/stamps");
    const items = r.data?.stamps || [];
    setStamps(items);
    return items;
  } catch (e) {
    showErr(e);
    return [];
  }
};

  const loadOrg = async () => {
    try {
      const r = await api.get("/orgs/me");
      setOrgInfo(r.data?.organization || null);
    } catch (e) {
      if (e?.response?.status !== 400) showErr(e);
    }
  };

  const loadTeam = async () => {
    try {
      const r = await api.get("/orgs/team");
      setTeam(r.data?.users || []);
    } catch (e) {
      if (e?.response?.status !== 400) showErr(e);
    }
  };

  const loadApiKeys = async () => {
    try {
      const r = await api.get("/apikeys");
      setApiKeys(r.data?.keys || []);
    } catch (e) {
      if (e?.response?.status !== 404 && e?.response?.status !== 400) {
        showErr(e);
      }
    }
  };

  const loadAudit = async () => {
    clearErr();
    try {
      const r = await api.get("/audit/my", { params: { limit: 50 } });
      setAudit(r.data?.items || []);
    } catch (e) {
      showErr(e);
    }
  };

  const chooseAuditForShare = async (auditId) => {
  if (!auditId) return;
  clearErr();
  try {
    setSelectedAuditForShare(auditId);
    const r = await api.get(`/verify/share/template/${auditId}`);
    const template = r.data || null;
    setShareTemplate(template);
    setShareForm((prev) => ({
      ...prev,
      subject: template?.subject || prev.subject || "",
    }));
  } catch (e) {
    showErr(e);
  }
};

const sendShareEmail = async () => {
  if (!selectedAuditForShare) return alert("Choose an audit row first.");
  if (!shareForm.to.trim()) return alert("Enter at least one recipient email.");
  clearErr();
  setShareSending(true);
  try {
    const r = await api.post("/verify/share/send", {
      auditId: selectedAuditForShare,
      to: shareForm.to,
      cc: shareForm.cc,
      bcc: shareForm.bcc,
      subject: shareForm.subject,
      note: shareForm.note,
    });
    showSuccess(
      `Branded email sent successfully to ${
        r.data?.to?.join(", ") || shareForm.to
      }.`
    );
    await loadAudit();
    await loadOrg();
    await loadDeliveries();
  } catch (e) {
    showErr(e);
  } finally {
    setShareSending(false);
  }
};

const sendTestEmail = async () => {
  clearErr();
  setShareSending(true);
  try {
    const to = brandingForm.reply_to || me?.email || email || "";
    const r = await api.post("/verify/share/test", { to });
    showSuccess(`Test email sent to ${r.data?.to || to}.`);
    await loadOrg();
    await loadAudit();
    await loadDeliveries();
  } catch (e) {
    showErr(e);
  } finally {
    setShareSending(false);
  }
};

const loadDeliveries = async () => {
  if (!me) return;
  setDeliveryLoading(true);
  try {
    const r = await api.get("/verify/share/deliveries", {
      params: { limit: 20 },
    });
    setDeliveries(r.data?.items || []);
  } catch (e) {
    if (e?.response?.status !== 404) showErr(e);
  } finally {
    setDeliveryLoading(false);
  }
};

const resendDelivery = async (deliveryId) => {
  if (!deliveryId) return;
  clearErr();
  setResendingDeliveryId(String(deliveryId));
  try {
    const r = await api.post(`/verify/share/resend/${deliveryId}`);
    showSuccess(
      r.data?.delivery?.status === "sent"
        ? "Email resent successfully."
        : "Resend request completed."
    );
    await loadDeliveries();
    await loadOrg();
    await loadAudit();
  } catch (e) {
    showErr(e);
    await loadDeliveries();
    await loadOrg();
  } finally {
    setResendingDeliveryId("");
  }
};
  const updateBrandingField = (key, value) => {
    setBrandingForm((prev) => ({ ...prev, [key]: value }));
  };

  const uploadPdf = async () => {
    if (!file) return alert("Choose a PDF first.");
    clearErr();

    try {
      const fd = new FormData();
      fd.append("file", file);

      const r = await api.post("/documents/upload/documents", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const docId = r.data?.document?.id || null;
      setLastDocId(docId);
      setStampPage(0);
      setErr(`Uploaded document id: ${docId || "unknown"}`);
      await loadAudit();
      await loadOrg();
    } catch (e) {
      showErr(e);
    }
  };

  const applyStamp = async () => {
    if (!selectedStamp) return alert("Choose a stamp first.");
    if (!lastDocId) return alert("Upload a PDF document first.");
    if (!stampPassword) return alert("Enter the stamp password.");

    clearErr();
    setApplyResult(null);

    try {
      const r = await api.post(`/stamps/${selectedStamp}/apply`, {
        documentId: lastDocId,
        page: Number(stampPage) || 0,
        x: Number(stampX) || 0,
        y: Number(stampY) || 0,
        scale: Number(stampScale) || 1,
        opacity: Number(stampOpacity) || 1,
        password: stampPassword,
      });

      setApplyResult(r.data || null);

      const outputName = `stamped-${lastDocId || "document"}.pdf`;

      if (r.data?.downloadUrl) {
        await smartDownloadFromUrl(r.data.downloadUrl, outputName);
      } else if (r.data?.downloadPath) {
        const fullUrl = `${api.defaults.baseURL}${r.data.downloadPath}`;
        await smartDownloadFromUrl(fullUrl, outputName);
      }

      await loadAudit();
      await loadOrg();
    } catch (e) {
  console.error(e);

  const msg =
    e?.response?.data?.detail ||
    e?.response?.data?.error ||
    e?.message ||
    "Failed to apply stamp";

  setErr(msg);
}
  };

  const uploadBulkPdfs = async () => {
    if (!bulkFiles.length) return alert("Choose PDF files first.");
    clearErr();
    setBulkDocumentIds([]);
    setBulkResults([]);

    try {
      const ids = [];
      for (const f of bulkFiles) {
        const fd = new FormData();
        fd.append("file", f);
        const r = await api.post("/documents/upload/documents", fd, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        const docId = r.data?.document?.id;
        if (docId) ids.push({ id: docId, name: f.name });
      }
      setBulkDocumentIds(ids);
      setErr(`Uploaded ${ids.length} documents for bulk stamping.`);
      await loadOrg();
    } catch (e) {
      showErr(e);
    }
  };

  const useFirstBulkFileForPreview = () => {
  if (!bulkFiles.length) return alert("No bulk PDF selected.");
  setBrowserPreviewBlocked(false);
  setPreviewPdfFile(bulkFiles[0]);
  setPreviewLoaded(false);
  setStampPage(0);
};

  const applyBulkStamp = async () => {
    if (!selectedStamp) return alert("Choose a stamp first.");
    if (!bulkDocumentIds.length) return alert("Upload bulk PDFs first.");
    if (!stampPassword) return alert("Enter the stamp password.");

    clearErr();
    setBulkResults([]);

    try {
      const r = await api.post(`/stamps/${selectedStamp}/apply-bulk`, {
        documentIds: bulkDocumentIds.map((d) => d.id),
        page: Number(stampPage) || 0,
        x: Number(stampX) || 0,
        y: Number(stampY) || 0,
        scale: Number(stampScale) || 1,
        opacity: Number(stampOpacity) || 1,
        password: stampPassword,
      });

      setBulkResults(r.data?.results || []);
      await loadAudit();
      await loadOrg();
    } catch (e) {
      showErr(e);
    }
  };

  const downloadBulkZip = async () => {
    if (!selectedStamp) return alert("Choose a stamp first.");
    if (!bulkDocumentIds.length) return alert("Upload bulk PDFs first.");
    if (!stampPassword) return alert("Enter the stamp password.");

    clearErr();

    try {
      const response = await api.post(
        `/stamps/${selectedStamp}/apply-bulk-zip`,
        {
          documentIds: bulkDocumentIds.map((d) => d.id),
          page: Number(stampPage) || 0,
          x: Number(stampX) || 0,
          y: Number(stampY) || 0,
          scale: Number(stampScale) || 1,
          opacity: Number(stampOpacity) || 1,
          password: stampPassword,
        },
        { responseType: "blob" }
      );

      downloadBlobFile(
        new Blob([response.data], { type: "application/zip" }),
        "bulk-stamped.zip"
      );
      await loadOrg();
    } catch (e) {
      showErr(e);
    }
  };

  const verifyPdf = async () => {
    if (!verifyFile) return alert("Please choose a PDF first");
    clearErr();
    setVerifyResult(null);

    try {
      const fd = new FormData();
      fd.append("file", verifyFile);
      const r = await api.post("/verify", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setVerifyResult(r.data || null);
    } catch (e) {
      showErr(e);
    }
  };

  const createOrg = async () => {
    if (!orgName.trim()) return alert("Enter organization name");
    clearErr();
    try {
      const r = await api.post("/orgs", { name: orgName });
      setOrgInfo(r.data?.organization || null);
      setOrgName("");
      await loadTeam();
      await loadBillingStatus();
    } catch (e) {
      showErr(e);
    }
  };

  const saveBranding = async () => {
    clearErr();
    try {
      const r = await api.post("/orgs/branding", brandingForm);
      setOrgInfo(r.data?.organization || null);
      showSuccess("Brand settings saved.");
    } catch (e) {
      showErr(e);
    }
  };

function getStampPlacementStorageKey(stampId) {
  return `estamp:lastPlacement:${String(stampId || "")}`;
}

function loadSavedStampPlacement(stampId) {
  if (!stampId) return null;

  try {
    const raw = localStorage.getItem(getStampPlacementStorageKey(stampId));
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;

    return {
      page: Number(parsed.page || 0),
      x: Number(parsed.x || 50),
      y: Number(parsed.y || 50),
      scale: Number(parsed.scale || 1),
      opacity: Number(parsed.opacity || 1),
    };
  } catch {
    return null;
  }
}

function clearSavedStampPlacement(stampId) {
  if (!stampId) return;
  try {
    localStorage.removeItem(getStampPlacementStorageKey(stampId));
  } catch {}
}

function saveStampPlacement(stampId, placement) {
  if (!stampId || !placement) return;

  try {
    localStorage.setItem(
      getStampPlacementStorageKey(stampId),
      JSON.stringify({
        page: Number(placement.page || 0),
        x: Number(placement.x || 50),
        y: Number(placement.y || 50),
        scale: Number(placement.scale || 1),
        opacity: Number(placement.opacity || 1),
      })
    );
  } catch {}
}

 function pickPreviewTemplate(stamp) {
  const preset = String(stamp?.customization?.presetTemplate || "").toLowerCase();
  const shape = String(stamp?.customization?.shape || "").toLowerCase();
  const name = String(stamp?.name || "").toLowerCase();

  const w = Number(stamp?.width || 0);
  const h = Number(stamp?.height || 0);
  const aspect = w > 0 && h > 0 ? w / h : null;

  const explicitCircle =
    preset.includes("circle") ||
    preset.includes("round") ||
    shape.includes("circle") ||
    shape.includes("round");

  const explicitRect =
    preset.includes("rect") ||
    preset.includes("rectangle") ||
    preset.includes("business") ||
    shape.includes("rect") ||
    shape.includes("rectangle") ||
    shape.includes("square");

  if (preset.includes("business") || name.includes("business")) {
    return "businessRect";
  }

  if (explicitCircle) {
    return name.includes("official") || preset.includes("official")
      ? "officialCircle"
      : "genericCircle";
  }

  if (explicitRect) {
    if (name.includes("official") || preset.includes("official")) {
      return "officialRect";
    }
    return aspect && aspect < 0.9 ? "genericTallRect" : "genericWideRect";
  }

  if (name.includes("official")) {
    return aspect && Math.abs(aspect - 1) < 0.18
      ? "officialCircle"
      : "officialRect";
  }

  if (aspect && Math.abs(aspect - 1) < 0.18) return "genericCircle";
  if (aspect && aspect < 0.9) return "genericTallRect";
  return "genericWideRect";
}

const PREVIEW_TEMPLATE_PRESETS = {
  officialCircle: {
    shape: "circle",
    qr: { x: 0.5, y: 0.28, size: 0.14, anchor: "center" },
  },
  genericCircle: {
    shape: "circle",
    qr: { x: 0.5, y: 0.28, size: 0.14, anchor: "center" },
  },
  businessRect: {
    shape: "rect",
    qr: { x: 0.10, y: 0.14, size: 0.14, anchor: "top-right-box" },
  },
  officialRect: {
    shape: "rect",
    qr: { x: 0.10, y: 0.14, size: 0.14, anchor: "top-right-box" },
  },
  genericWideRect: {
    shape: "rect",
    qr: { x: 0.10, y: 0.14, size: 0.14, anchor: "top-right-box" },
  },
  genericTallRect: {
    shape: "rect",
    qr: { x: 0.10, y: 0.14, size: 0.14, anchor: "top-right-box" },
  },
};

function getPreviewZone(stamp) {
  const key = pickPreviewTemplate(stamp);
  return PREVIEW_TEMPLATE_PRESETS[key] || PREVIEW_TEMPLATE_PRESETS.genericWideRect;
}

  const inviteTeammate = async () => {
    if (!inviteEmail.trim()) return alert("Enter teammate email");
    clearErr();
    try {
      await api.post("/orgs/invite", {
        email: inviteEmail,
        role: inviteRole,
      });
      setInviteEmail("");
      setInviteRole("user");
      await loadTeam();
    } catch (e) {
      showErr(e);
    }
  };

  const resendInvite = async (userId) => {
    clearErr();
    setTeamBusyId(String(userId));
    try {
      await api.post(`/orgs/team/${userId}/resend`);
      showSuccess("Invite resent.");
      await loadTeam();
    } catch (e) {
      showErr(e);
    } finally {
      setTeamBusyId("");
    }
  };

  const cancelInvite = async (userId) => {
    if (!window.confirm("Cancel this pending invite?")) return;
    clearErr();
    setTeamBusyId(String(userId));
    try {
      await api.post(`/orgs/team/${userId}/cancel-invite`);
      showSuccess("Invite canceled.");
      await loadTeam();
    } catch (e) {
      showErr(e);
    } finally {
      setTeamBusyId("");
    }
  };

  const changeTeamRole = async (userId, role) => {
    clearErr();
    setTeamBusyId(String(userId));
    try {
      await api.patch(`/orgs/team/${userId}/role`, { role });
      showSuccess("Team role updated.");
      await loadTeam();
    } catch (e) {
      showErr(e);
    } finally {
      setTeamBusyId("");
    }
  };

  const removeTeammate = async (userId, memberEmail) => {
    if (!window.confirm(`Remove ${memberEmail} from this organization?`)) return;
    clearErr();
    setTeamBusyId(String(userId));
    try {
      await api.delete(`/orgs/team/${userId}`);
      showSuccess("Teammate removed.");
      await loadTeam();
    } catch (e) {
      showErr(e);
    } finally {
      setTeamBusyId("");
    }
  };

  const createApiKey = async () => {
    clearErr();
    try {
      const r = await api.post("/apikeys", {
        name: newKeyName.trim() || "Default Key",
      });
      setNewKey(r.data?.rawKey || null);
      setNewKeyName("Default Key");
      await loadApiKeys();
      showSuccess("API key created.");
    } catch (e) {
      showErr(e);
    }
  };

  const copyToClipboard = async (value, successMsg = "Copied.") => {
    try {
      await navigator.clipboard.writeText(String(value || ""));
      showSuccess("Copied.");
    } catch {
      setErr("Copy failed.");
    }
  };

  const deleteApiKey = async (id) => {
  clearErr();
  try {
    await api.delete(`/apikeys/${id}`);
    await loadApiKeys();
    showSuccess("API key deleted.");
  } catch (e) {
    showErr(e);
  }
};

const previewZone = getPreviewZone(selectedStampObj);
const previewShape = previewZone?.shape || "rect";

const currentPlan = String(
  billingStatus?.plan ||
    billingStatus?.currentPlan ||
    billingStatus?.subscription?.plan ||
    orgInfo?.plan ||
    me?.plan ||
    "free"
).toLowerCase();

  const usage = orgInfo?.usage || {};
  const planMeta = orgInfo?.planMeta || {};
  const usagePercentages = planMeta?.usagePercentages || {};
  const branding = orgInfo?.branding || {};
  const emailSettings = orgInfo?.emailSettings || {};
  const brandPrimary = branding?.primary_color || "#1d4ed8";
  const brandAccent = branding?.accent_color || "#0f172a";

  const pricingPlans = [
    {
      key: "free",
      name: "Free",
      price: "$0",
      subtitle: "Get started",
      highlights: [
        "10 documents / month",
        "25 stamp actions / month",
        "Watermarked exports",
        "50 MB storage",
      ],
    },
    {
      key: "pro",
      name: "Pro",
      price: "$19/mo",
      subtitle: "Solo power users",
      highlights: [
        "250 documents / month",
        "Upload your real stamp",
        "Add logo on preset stamps",
        "No platform watermark",
        "1 GB storage",
      ],
    },
    {
      key: "business",
      name: "Business",
      price: "$59/mo",
      subtitle: "Teams and API access",
      highlights: [
        "Custom stamp designer + actual stamp upload",
        "Logo on preset stamp layouts",
        "ZIP export",
        "Team members",
        "API keys",
        "10 GB storage",
      ],
    },
  ];

  const usageCards = [
    {
      key: "documentsThisMonth",
      label: "Documents this month",
      used: Number(usage?.documentsThisMonth || 0),
      limit: planMeta?.limits?.documentsThisMonth,
      percent: Number(usagePercentages?.documentsThisMonth || 0),
    },
    {
      key: "stampsThisMonth",
      label: "Stamp actions this month",
      used: Number(usage?.stampsThisMonth || 0),
      limit: planMeta?.limits?.stampsThisMonth,
      percent: Number(usagePercentages?.stampsThisMonth || 0),
    },
    {
      key: "storageUsedMB",
      label: "Storage used",
      used: Number(usage?.storageUsedMB || 0).toFixed(2),
      limit: planMeta?.limits?.storageUsedMB,
      percent: Number(usagePercentages?.storageUsedMB || 0),
      unit: "MB",
    },
  ];

  const featureRows = [
    { key: "analytics", label: "Analytics reports" },
    { key: "bulkStamping", label: "Bulk stamping" },
    { key: "zipExport", label: "ZIP export" },
    { key: "customStampDesigner", label: "Custom stamp designer" },
    { key: "actualStampUpload", label: "Upload actual stamp" },
    { key: "brandedPresetLogo", label: "Logo on preset stamps" },
    { key: "brandedOrganization", label: "Organization branding" },
    { key: "customBrandKit", label: "Advanced brand kit" },
    { key: "watermarkRemoval", label: "No platform watermark" },
    { key: "teamAccess", label: "Team members" },
    { key: "apiAccess", label: "API access" },
    { key: "billingPortal", label: "Self-serve billing" },
    { key: "serverSideEmailSharing", label: "Server-side email sending" },
  ];

  const verifyDetails = verifyResult?.details || {};
  const embedded = verifyResult?.embedded || {};
  const embeddedPayload = embedded?.payload || {};
  const verified = !!verifyResult?.verified;

  const cardStyle = {
    background: "#ffffff",
    border: "1px solid #dbe4f0",
    borderRadius: 16,
    padding: 22,
    boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)",
    marginBottom: 20,
  };

  const sectionTitle = {
    marginTop: 0,
    marginBottom: 16,
    fontSize: 28,
    color: "#0f172a",
    letterSpacing: "-0.02em",
  };

  const inputStyle = {
    padding: "10px 12px",
    borderRadius: 10,
    border: "1px solid #cbd5e1",
    minWidth: 220,
    fontSize: 15,
    background: "#fff",
    color: "#0f172a",
  };

  const labelStyle = {
    display: "block",
    marginBottom: 6,
    fontWeight: 600,
    color: "#374151",
  };

  const buttonStyle = {
    background: "#1d4ed8",
    color: "#fff",
    border: "none",
    borderRadius: 10,
    padding: "10px 16px",
    cursor: "pointer",
    fontWeight: 700,
    boxShadow: "0 2px 8px rgba(29, 78, 216, 0.18)",
  };

  const buttonSecondary = {
    background: "#eff6ff",
    color: "#1d4ed8",
    border: "1px solid #bfdbfe",
    borderRadius: 10,
    padding: "10px 16px",
    cursor: "pointer",
    fontWeight: 700,
  };

  const thStyle = {
    textAlign: "left",
    padding: 12,
    borderBottom: "1px solid #e5e7eb",
  };

  const tdStyle = {
    padding: 12,
    verticalAlign: "top",
  };

  const canUseAnalytics = !!planMeta?.features?.analytics;
  const canUseBulk = !!planMeta?.features?.bulkStamping;
  const canUseZip = !!planMeta?.features?.zipExport;
  const canUseApi = !!planMeta?.features?.apiAccess;
  const canUseTeam = !!planMeta?.features?.teamAccess;

  const shareableAudits = audit.filter(
  (it) =>
    !!(
      it?._id &&
      (it?.verification_code ||
        it?.meta?.verifyCode ||
        it?.meta?.verification_code ||
        it?.verification?.payload?.verify_code)
    )
);

//const effectivePreviewBoxWidth = previewBoxWidth;
//const effectivePreviewBoxHeight = previewBoxHeight;

const selectedAuditRecord =
  shareableAudits.find(
    (it) => String(it._id) === String(selectedAuditForShare)
  ) || null;

  return (
    <div
      style={{
        fontFamily: "Arial, sans-serif",
        background: "linear-gradient(180deg, #f8fbff 0%, #f1f5f9 100%)",
        minHeight: "100vh",
        padding: "24px",
        color: "#1f2937",
      }}
    >
      <div style={{ maxWidth: 1280, margin: "0 auto" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 12,
            flexWrap: "wrap",
            marginBottom: 24,
          }}
        >
          <div>
            <h1 style={{ margin: 0, fontSize: 42 }}>eStamp Pro</h1>
            <div style={{ color: "#64748b", marginTop: 4, fontSize: 15 }}>
              Secure digital stamping, verification, and document trust
            </div>
          </div>

          <div
            style={{
              display: "flex",
              gap: 10,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <div
              style={{
                background: "#eff6ff",
                border: "1px solid #bfdbfe",
                borderRadius: 999,
                padding: "8px 12px",
                fontWeight: 700,
                color: "#1d4ed8",
              }}
            >
              Current plan: {currentPlan}
            </div>

            {currentPlan === "free" ? (
  <button
    style={buttonStyle}
    onClick={() => upgradePlan("pro")}
  >
    Upgrade
  </button>
) : (
  <button
    style={buttonSecondary}
    onClick={openBillingPortal}
  >
    Manage Billing
  </button>
)}
            

            {billingStatus?.cancel_at_period_end && (
              <div
                style={{
                  background: "#fff7ed",
                  border: "1px solid #fdba74",
                  color: "#9a3412",
                  borderRadius: 999,
                  padding: "8px 12px",
                  fontWeight: 700,
                }}
              >
                Cancels at period end
              </div>
            )}

            <div
              style={{
                background: "#ffffff",
                border: "1px solid #dbe4f0",
                borderRadius: 12,
                padding: "10px 14px",
              }}
            >
              <strong>User:</strong> {me?.email || "Not logged in"}
            </div>
          </div>
        </div>

        {err && (
  <div
    style={{
      background: "#fff1f2",
      border: "1px solid #fecdd3",
      color: "#9f1239",
      padding: 14,
      borderRadius: 12,
      marginBottom: 20,
      fontWeight: 600,
    }}
  >
    <div>{err}</div>
    {upgradeHint && (
      <div
        style={{
          marginTop: 10,
          color: "#7f1d1d",
          fontWeight: 500,
        }}
      >
        Current plan:{" "}
        <strong>{upgradeHint.currentPlan || currentPlan}</strong>
        {upgradeHint.limitKey ? ` • Limit: ${upgradeHint.limitKey}` : ""}
        <div
          style={{
            marginTop: 10,
            display: "flex",
            gap: 10,
            flexWrap: "wrap",
          }}
        >
          {currentPlan !== "business" ? (
  <>
    {currentPlan === "free" && (
      <button style={buttonSecondary} onClick={() => upgradePlan("pro")}>
        Upgrade to Pro
      </button>
    )}

    <button style={buttonStyle} onClick={() => upgradePlan("business")}>
      Upgrade to Business
    </button>
  </>
) : (
  <div style={{ fontWeight: 700, color: "#065f46" }}>
    You are already on Business. This block is not a plan-limit issue.
  </div>
)}
        </div>
      </div>
    )}
  </div>
)}

{success && (
  <div
    style={{
      background: "#ecfdf5",
      border: "1px solid #a7f3d0",
      color: "#065f46",
      padding: 14,
      borderRadius: 12,
      marginBottom: 20,
      fontWeight: 600,
    }}
  >
    {success}
  </div>
)}

<div
  style={{
    display: "flex",
    gap: 10,
    flexWrap: "wrap",
    marginBottom: 20,
    padding: 10,
    background: "#ffffff",
    border: "1px solid #dbe4f0",
    borderRadius: 999,
  }}
>
  {tabs.map((tab) => (
    <button
      key={tab.key}
      type="button"
      style={tabButton(tab.key)}
      onClick={() => setActiveTab(tab.key)}
    >
      {tab.label}
    </button>
  ))}
</div>

    {activeTab === "stamp" && (
  <>
    <section style={cardStyle}>
      <h2 style={sectionTitle}>Upload PDF</h2>
            <div
              style={{
                display: "flex",
                gap: 10,
                flexWrap: "wrap",
                alignItems: "center",
              }}
            >
             <input
  type="file"
  accept="application/pdf"
  onChange={(e) => {
    const f = e.target.files?.[0] || null;
    setFile(f);
    setBulkFiles([]);
    setBrowserPreviewBlocked(false);
    setPreviewPdfFile(f);
    setPreviewLoaded(false);
    setPreviewPageCount(0);
    setStampPage(0);
  }}
/>
              <button style={buttonStyle} onClick={uploadPdf}>
                Upload
              </button>
            </div>
            <div style={{ marginTop: 14 }}>
              <strong>Last uploaded document id:</strong> {lastDocId || "—"}
            </div>
            <div
  style={{
    background: "#eff6ff",
    border: "1px solid #bfdbfe",
    color: "#1e40af",
    borderRadius: 12,
    padding: "10px 14px",
    marginTop: 12,
    fontSize: 14,
    lineHeight: 1.5,
    fontWeight: 500,
  }}
>
  Note: If your PDF is password-protected, open it and save a new unlocked copy before uploading for stamping.
</div>
          </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Stamp Designer</h2>
          
  <StampDesigner
  onSaved={async (savedStamp) => {
    const items = await loadStamps();
    await loadOrg();

    const nextId = String(savedStamp?.id || savedStamp?._id || "");
    const exists = items.find(
      (s) => String(s._id || s.id) === nextId
    );

    if (exists) {
      setSelectedStamp(String(exists._id || exists.id));
      showSuccess(`Stamp saved and selected: ${exists.name || "New stamp"}`);
    } else {
      showSuccess("Stamp saved successfully.");
    }
  }}
  canCustomize={!!planMeta?.features?.customStampDesigner}
  canUploadActual={!!planMeta?.features?.actualStampUpload}
  canUsePresetLogo={!!planMeta?.features?.brandedPresetLogo}
  currentPlan={currentPlan}
  onUpgrade={() => openUpgradeModal("pro_branding")}
  branding={branding}
/>
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Apply Stamp</h2>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 20,
              alignItems: "start",
            }}
          >
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div>
                  <label style={labelStyle}>Stamp</label>
                  <select
                    style={{ ...inputStyle, width: "100%" }}
                    value={selectedStamp}
                    onChange={(e) => setSelectedStamp(e.target.value)}
                  >
                    <option value="">Choose a stamp</option>
                    {stamps.map((s) => (
                      <option key={String(s._id || s.id)} value={String(s._id || s.id)}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={labelStyle}>Stamp password</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="password"
                    value={stampPassword}
                    onChange={(e) => setStampPassword(e.target.value)}
                    placeholder="Required"
                  />
                </div>

                <div>
                  <label style={labelStyle}>Page</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="number"
                    value={stampPage}
                    onChange={(e) => setStampPage(e.target.value)}
                  />
                </div>

                <div>
                  <label style={labelStyle}>Scale</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="number"
                    step="0.1"
                    value={stampScale}
                    onChange={(e) => setStampScale(e.target.value)}
                  />
                </div>

                <div>
                  <label style={labelStyle}>X</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="number"
                    value={stampX}
                    onChange={(e) => setStampX(e.target.value)}
                  />
                </div>

                <div>
                  <label style={labelStyle}>Y</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="number"
                    value={stampY}
                    onChange={(e) => setStampY(e.target.value)}
                  />
                </div>

                <div>
                  <label style={labelStyle}>Opacity</label>
                  <input
                    style={{ ...inputStyle, width: "100%" }}
                    type="number"
                    step="0.1"
                    min="0"
                    max="1"
                    value={stampOpacity}
                    onChange={(e) => setStampOpacity(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button style={buttonStyle} onClick={applyStamp}>
                  Apply Stamp
                </button>
              </div>

              {applyResult && (
                <div
                  style={{
                    marginTop: 16,
                    padding: 14,
                    borderRadius: 12,
                    border: "1px solid #dbe4f0",
                    background: "#f8fafc",
                  }}
                >
                  <div><strong>Verification code:</strong> {applyResult.verifyCode || "—"}</div>
                  <div><strong>Audit id:</strong> {applyResult.audit_id || "—"}</div>
                </div>
              )}
            </div>

            <div>
              <div style={{ fontWeight: 700, marginBottom: 10 }}>Preview placement</div>
  <div
  ref={previewFrameRef}
  style={{
    border: "1px solid #dbe4f0",
    borderRadius: 14,
    background: "#fff",
    minHeight: 400,
    overflow: "auto",
    padding: 12,
  }}
>
  {previewPdfFile ? (
    <div
      ref={pageRef}
      style={{
        position: "relative",
        width: previewRenderWidth,
        margin: "0 auto",
        isolation: "isolate",
      }}
    >
      {browserPreviewBlocked ? (
  <div style={{ padding: 20, color: "#64748b" }}>
    Browser preview unavailable for this encrypted PDF.
  </div>
) : (
  <PdfDocument
    file={previewPdfFile}
  onLoadSuccess={({ numPages }) => {
    const total = numPages || 0;
    setPreviewPageCount(total);
    setPreviewLoaded(true);

    if (total > 0) {
      const current = Number(stampPage || 0);
      if (current > total - 1) {
        setStampPage(total - 1);
      }
    }

    requestAnimationFrame(() => {
      const saved = selectedStamp
        ? loadSavedStampPlacement(selectedStamp)
        : null;

      if (saved) {
        syncPreviewFromPdfCoords();
      } else {
        placeStampPreset("bottom-right");
      }
    });
  }}
  onLoadError={(e) => {
    console.warn("Preview PDF render failed", e);
    setPreviewLoaded(false);
    setErr(
      "This PDF is encrypted and cannot be shown in the browser preview. You can still use exact stamped preview or apply the stamp."
    );
  }}
  onPassword={() => {
  setBrowserPreviewBlocked(true);
  setPreviewLoaded(false);
  setErr(
    "This PDF is encrypted. Browser preview needs the PDF open password, not the stamp password. The backend can still stamp it."
  );
}}
>
  <Page
          pageNumber={Math.max(1, Number(stampPage || 0) + 1)}
          width={previewRenderWidth}
          renderAnnotationLayer
          renderTextLayer
        />
      </PdfDocument>
)}

      {selectedStamp && (
        <div
          ref={boxRef}
          onPointerDown={handlePreviewPointerDown}
          style={{
  position: "absolute",
  left: dragX,
  top: dragY,
  width: effectivePreviewBoxWidth,
  height: effectivePreviewBoxHeight,
  background: hasRealStampPreview ? "transparent" : "rgba(37, 99, 235, 0.10)",
  border: hasRealStampPreview ? "none" : "2px solid #2563eb",
  borderRadius: hasRealStampPreview
    ? 0
    : previewShape === "circle"
    ? "9999px"
    : 10,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  color: "#1d4ed8",
  fontWeight: 700,
  cursor: "grab",
  userSelect: "none",
  touchAction: "none",
  pointerEvents: "auto",
  zIndex: 20,
  boxSizing: "border-box",
  overflow: "visible",
}}
        >
       {hasRealStampPreview ? (
  <img
  src={previewStampSrc}
  alt="Selected stamp preview"
  draggable={false}
  onLoad={(e) => {
    const img = e.currentTarget;
    setPreviewImageMeta({
      naturalWidth: img.naturalWidth || 0,
      naturalHeight: img.naturalHeight || 0,
    });
  }}
  style={{
    width: "100%",
    height: "100%",
    objectFit: "fill",
    display: "block",
    pointerEvents: "none",
    userSelect: "none",
  }}
/>
  
) : (
  <>
    <div
      style={{
        position: "absolute",
        inset: previewShape === "circle" ? "10%" : "6%",
        border: "1px solid rgba(37, 99, 235, 0.65)",
        borderRadius: previewShape === "circle" ? "9999px" : 8,
        pointerEvents: "none",
      }}
    />

    <div
      style={{
        position: "absolute",
        left:
          previewZone.qr.anchor === "top-right-box"
            ? `${100 - previewZone.qr.x * 100 - previewZone.qr.size * 100}%`
            : `${previewZone.qr.x * 100 - (previewZone.qr.size * 100) / 2}%`,
        top:
          previewZone.qr.anchor === "top-right-box"
            ? `${previewZone.qr.y * 100}%`
            : `${previewZone.qr.y * 100 - (previewZone.qr.size * 100) / 2}%`,
        width: `${previewZone.qr.size * 100}%`,
        height: `${previewZone.qr.size * 100}%`,
        border: "1px dashed #2563eb",
        background: "rgba(37, 99, 235, 0.10)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 10,
        pointerEvents: "none",
      }}
    >
      QR
    </div>

    <div
      style={{
        fontSize: 14,
        fontWeight: 700,
        pointerEvents: "none",
      }}
    >
      Stamp
    </div>
  </>
)}
        </div>
      )}
    </div>
  ) : (
    <div style={{ padding: 24, color: "#64748b" }}>
      Upload a PDF or select the first bulk file to preview placement.
    </div>
  )}
</div>

              {previewPdfFile && (
                <div style={{ marginTop: 8, color: "#64748b", fontSize: 14 }}>
                  Pages detected: {previewPageCount || "—"}
                </div>
              )}
{previewPdfFile && previewPageCount > 1 && (
  <div
    style={{
      marginTop: 12,
      display: "flex",
      gap: 10,
      alignItems: "center",
      flexWrap: "wrap",
    }}
  >
    <button
      style={buttonSecondary}
      onClick={() =>
        setStampPage((prev) => Math.max(0, Number(prev || 0) - 1))
      }
      disabled={Number(stampPage || 0) <= 0}
    >
      Previous page
    </button>

    <div
      style={{
        padding: "8px 12px",
        border: "1px solid #dbe4f0",
        borderRadius: 10,
        background: "#fff",
      }}
    >
      Previewing page {Number(stampPage || 0) + 1} of {previewPageCount}
    </div>

    <button
      style={buttonSecondary}
      onClick={() =>
        setStampPage((prev) =>
          Math.min(previewPageCount - 1, Number(prev || 0) + 1)
        )
      }
      disabled={Number(stampPage || 0) >= previewPageCount - 1}
    >
      Next page
    </button>

    <button
      style={buttonSecondary}
      onClick={() => setStampPage(previewPageCount - 1)}
    >
      Jump to last page
    </button>
  </div>
)}

{previewPdfFile && (
  <div
    style={{
      marginTop: 12,
      display: "flex",
      gap: 10,
      flexWrap: "wrap",
      alignItems: "center",
    }}
  >
    <span style={{ fontWeight: 700, color: "#334155" }}>Quick place:</span>

<button
  type="button"
  style={buttonStyle}
  onClick={placeStampSmart}
>
  Smart Place
</button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("top-left")}
    >
      Top Left
    </button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("top-right")}
    >
      Top Right
    </button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("bottom-left")}
    >
      Bottom Left
    </button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("bottom-right")}
    >
      Bottom Right
    </button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("center-right")}
    >
      Center Right
    </button>

    <button
      type="button"
      style={buttonSecondary}
      onClick={() => placeStampPreset("center-left")}
    >
      Center Left
    </button>

    <button
  type="button"
  style={buttonSecondary}
  onClick={() => {
  if (selectedStamp) {
    clearSavedStampPlacement(selectedStamp);
  }

  setStampPage(0);
  setStampScale(1);
  setStampOpacity(1);

  requestAnimationFrame(() => {
    placeStampPreset("bottom-right");
  });
}}
>
  Reset Placement
</button>
  </div>
)}

            </div>
          </div>
        </section>

        <section style={cardStyle}>
  <h2 style={sectionTitle}>Exact stamped preview</h2>

  {!selectedStamp || !previewDocumentId ? (
    <div style={{ color: "#64748b" }}>
      Upload a PDF and choose a stamp to render the final preview.
    </div>
  ) : exactPreviewLoading ? (
    <div style={{ color: "#64748b" }}>Rendering exact preview...</div>
  ) : exactPreviewUrl ? (
    <PdfDocument
  file={exactPreviewUrl}
  //onPassword={() => {
    //setExactPreviewUrl("");
    //setExactPreviewLoading(false);
    //setErr(
      //"The exact preview PDF is encrypted and cannot be shown in the browser viewer, but stamping can still run from the backend."
    //);
  //}}
  //onLoadError={(e) => {
    //console.warn("Exact preview render failed", e);
    //setExactPreviewUrl("");
    //setExactPreviewLoading(false);
    //setErr(
      //"Exact preview could not be displayed in the browser, but you can still apply the stamp."
    //);
  //}}
>
  <Page
    pageNumber={Math.max(1, Number(stampPage || 0) + 1)}
    width={380}
    renderAnnotationLayer
    renderTextLayer
  />
</PdfDocument>
  ) : (
   <div style={{ color: "#64748b" }}>
  {!selectedStamp && "Select a stamp"}
  {selectedStamp && !previewDocumentId && "Upload a document"}
  {selectedStamp && previewDocumentId && !stampPassword && "Enter stamp password"}
  {selectedStamp && previewDocumentId && stampPassword && "Waiting for preview..."}
</div>
  )}
</section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Bulk Stamping</h2>
          <div style={{ marginBottom: 12, color: "#475569" }}>
            Upload multiple PDFs, then apply the selected stamp to all of them
            using the same settings.
          </div>

          {!canUseBulk && (
            <div
              style={{
                marginBottom: 14,
                padding: 12,
                borderRadius: 10,
                background: "#fffbeb",
                border: "1px solid #fde68a",
                color: "#92400e",
              }}
            >
              Bulk stamping unlocks on Pro. ZIP export unlocks on Business.
            </div>
          )}

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              alignItems: "center",
              marginBottom: 12,
            }}
          >
            <input
              type="file"
              accept="application/pdf"
              multiple
              onChange={(e) => {
                const files = Array.from(e.target.files || []);
                setBulkFiles(files);
                if (files.length > 0) {
                  setBrowserPreviewBlocked(false);
                  setPreviewPdfFile(files[0]);
                  setPreviewLoaded(false);
                }
              }}
            />
            <button style={buttonSecondary} onClick={uploadBulkPdfs}>
              Upload Bulk PDFs
            </button>
            <button style={buttonSecondary} onClick={useFirstBulkFileForPreview}>
              Preview First PDF
            </button>
            <button
              style={buttonStyle}
              onClick={() => {
                if (!canUseBulk) {
                  openUpgradeModal("pro_limits");
                  return;
                }
                applyBulkStamp();
              }}
            >
              Apply Stamp to All
            </button>
            <button
              style={buttonStyle}
              onClick={() => {
                if (!canUseZip) {
                  openUpgradeModal("business_zip");
                  return;
                }
                downloadBulkZip();
              }}
            >
              {canUseZip ? "Download ZIP" : "ZIP Export (Business)"}
            </button>
          </div>

          <div>
            <strong>Files selected:</strong> {bulkFiles.length}
          </div>

          {bulkDocumentIds.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <strong>Uploaded bulk documents:</strong>
              <ul>
                {bulkDocumentIds.map((d) => (
                  <li key={d.id}>
                    {d.name} — {d.id}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {bulkResults.length > 0 && (
            <div style={{ overflowX: "auto", marginTop: 16 }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <th style={thStyle}>Filename</th>
                    <th style={thStyle}>Status</th>
                    <th style={thStyle}>Verification Code</th>
                    <th style={thStyle}>Download</th>
                  </tr>
                </thead>
                <tbody>
                  {bulkResults.map((r, i) => (
                    <tr key={`${r.documentId}-${i}`}>
                      <td style={tdStyle}>{r.filename || r.documentId}</td>
                      <td style={tdStyle}>
                        {r.ok ? "Success" : `Failed: ${r.error || "unknown"}`}
                      </td>
                      <td style={tdStyle}>{r.verifyCode || "—"}</td>
                      <td style={tdStyle}>
                        {r.downloadUrl ? (
                          <a href={r.downloadUrl} target="_blank" rel="noreferrer">
                            Open
                          </a>
                        ) : r.downloadPath ? (
                          <a
                            href={`${api.defaults.baseURL}${r.downloadPath}`}
                            target="_blank"
                            rel="noreferrer"
                          >
                            Open
                          </a>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
  </>
)}
{activeTab === "org" && (
  <>
  {billingStatus && (
          <div
            style={{
              marginBottom: 18,
              padding: 14,
              borderRadius: 12,
              border: "1px solid #dbe4f0",
              background: "#f8fafc",
              color: "#334155",
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 6 }}>
              Subscription status
            </div>
            <div>
              <strong>Status:</strong>{" "}
              {billingStatus.subscription_status || "inactive"}
            </div>
            <div>
              <strong>Plan:</strong> {billingStatus.plan || currentPlan}
            </div>
            <div>
              <strong>Current period end:</strong>{" "}
              {billingStatus.current_period_end
                ? new Date(billingStatus.current_period_end).toLocaleDateString()
                : "—"}
            </div>
          </div>
        )}
        <section style={cardStyle}>
          <h2 style={sectionTitle}>Organization</h2>

          {!orgInfo ? (
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <input
                style={inputStyle}
                placeholder="Organization name"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
              />
              <button style={buttonStyle} onClick={createOrg}>
                Create Organization
              </button>
            </div>
          ) : (
            <>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1.2fr 0.8fr",
                  gap: 18,
                  marginBottom: 18,
                }}
              >
                <div
                  style={{
                    padding: 16,
                    border: "1px solid #dbe4f0",
                    borderRadius: 14,
                    background: "#f8fbff",
                  }}
                >
                  <div style={{ marginBottom: 10 }}>
                    <strong>Name:</strong> {orgInfo.name}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Slug:</strong> {orgInfo.slug}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Plan:</strong> {orgInfo.plan}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Stamp label:</strong>{" "}
                    {branding.stamp_label || "Official Organization Stamp"}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Primary color:</strong>{" "}
                    <span
                      style={{
                        display: "inline-block",
                        width: 14,
                        height: 14,
                        borderRadius: 999,
                        background: brandPrimary,
                        verticalAlign: "middle",
                        marginRight: 6,
                      }}
                    />{" "}
                    {brandPrimary}
                  </div>
                  <div>
                    <strong>Billing status:</strong>{" "}
                    {orgInfo?.billing?.subscription_status ||
                      orgInfo?.billing?.status ||
                      "inactive"}
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <strong>Current period end:</strong>{" "}
                    {orgInfo?.billing?.current_period_end
                      ? new Date(orgInfo.billing.current_period_end).toLocaleDateString()
                      : "—"}
                  </div>
                </div>

                <div
                  style={{
                    padding: 16,
                    border: "1px solid #dbe4f0",
                    borderRadius: 14,
                    background: "#ffffff",
                  }}
                >
                  <div style={{ fontWeight: 700, marginBottom: 10 }}>
                    Plan features
                  </div>
                  {featureRows.map((item) => (
                    <div
                      key={item.key}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        marginBottom: 8,
                      }}
                    >
                      <span>{item.label}</span>
                      <strong>
                        {planMeta?.features?.[item.key] ? "Included" : "Locked"}
                      </strong>
                    </div>
                  ))}
                </div>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: 14,
                  marginBottom: 20,
                }}
              >
                {usageCards.map((item) => {
                  const status = getUsageStatus(item.percent);

                  return (
                    <div
                      key={item.key}
                      style={{
                        border: `1px solid ${status.border}`,
                        borderRadius: 14,
                        padding: 14,
                        background: "#fff",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: 10,
                          alignItems: "center",
                          marginBottom: 10,
                        }}
                      >
                        <div style={{ fontWeight: 700 }}>{item.label}</div>
                        <div
                          style={{
                            padding: "4px 10px",
                            borderRadius: 999,
                            fontSize: 12,
                            fontWeight: 700,
                            background: status.bg,
                            color: status.color,
                            border: `1px solid ${status.border}`,
                          }}
                        >
                          {status.label}
                        </div>
                      </div>

                      <div style={{ color: "#334155", marginBottom: 6 }}>
                        {formatUsage(item.used, item.limit, item.unit || "")}
                      </div>

                      <div
                        style={{
                          fontSize: 13,
                          color: status.color,
                          fontWeight: 700,
                          marginBottom: 10,
                        }}
                      >
                        {item.percent}% used
                      </div>

                      <div
                        style={{
                          height: 10,
                          background: "#e2e8f0",
                          borderRadius: 999,
                          overflow: "hidden",
                          marginBottom: status.tone === "ok" ? 0 : 10,
                        }}
                      >
                        <div
                          style={{
                            width: `${Math.min(Number(item.percent || 0), 100)}%`,
                            height: "100%",
                            background: status.color,
                          }}
                        />
                      </div>

                      {status.tone !== "ok" && currentPlan !== "business" && (
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 10,
                            flexWrap: "wrap",
                          }}
                        >
                          <div style={{ fontSize: 13, color: "#475569" }}>
                            {status.tone === "warning" &&
                              "You are getting close to your monthly allowance."}
                            {status.tone === "critical" &&
                              "You are very close to the limit. Upgrade soon to avoid interruptions."}
                            {status.tone === "limit" &&
                              "This limit has been reached. Upgrade to continue without disruption."}
                          </div>

                          <button
                            style={buttonSecondary}
                            onClick={() =>
                              openUpgradeModal(getUpgradeFeatureKeyForUsage(item.key))
                            }
                          >
                            Upgrade
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: 14,
                  marginBottom: 22,
                }}
              >
                {pricingPlans.map((plan) => (
                  <div
                    key={plan.key}
                    style={{
                      border:
                        plan.key === currentPlan
                          ? "2px solid #1d4ed8"
                          : "1px solid #dbe4f0",
                      borderRadius: 16,
                      padding: 16,
                      background:
                        plan.key === currentPlan ? "#eff6ff" : "#fff",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 10,
                        alignItems: "center",
                        marginBottom: 10,
                      }}
                    >
                      <div>
                        <div style={{ fontSize: 18, fontWeight: 800 }}>
                          {plan.name}
                        </div>
                        <div style={{ color: "#64748b", marginTop: 2 }}>
                          {plan.subtitle}
                        </div>
                      </div>

                      {plan.key === currentPlan && (
                        <div
                          style={{
                            color: "#1d4ed8",
                            fontWeight: 800,
                            fontSize: 16,
                          }}
                        >
                          Current
                        </div>
                      )}
                    </div>

                    <div
                      style={{
                        fontSize: 28,
                        fontWeight: 900,
                        marginBottom: 10,
                        color: "#0f172a",
                      }}
                    >
                      {plan.price}
                    </div>

                    <ul
                      style={{
                        paddingLeft: 20,
                        marginTop: 0,
                        marginBottom: 16,
                        color: "#334155",
                      }}
                    >
                      {plan.highlights.map((item) => (
                        <li key={item} style={{ marginBottom: 6 }}>
                          {item}
                        </li>
                      ))}
                    </ul>

                   {(() => {
  const planButton = getPlanCardButton(plan.key);

  return planButton?.isCurrent ? (
    <div
      style={{
        display: "inline-block",
        padding: "10px 16px",
        borderRadius: 10,
        background: "#dbeafe",
        color: "#1d4ed8",
        fontWeight: 800,
      }}
    >
      Current Plan
    </div>
  ) : planButton ? (
    <button
      style={planButton.style}
      disabled={planButton.disabled}
      onClick={() =>
        planButton.billingPortal
          ? openBillingPortal()
          : upgradePlan(plan.key)
      }
    >
      {planButton.label}
    </button>
  ) : null;
})()}
                  </div>
                ))}
              </div>
            </>
          )}
        </section>

 </>
)}

{activeTab === "branding" && (
  <>
        <section style={cardStyle}>
          <h2 style={sectionTitle}>Branding</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 14,
            }}
          >
            <div>
              <label style={labelStyle}>Logo URL</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.logo_url}
                onChange={(e) => updateBrandingField("logo_url", e.target.value)}
              />
            </div>
            <div>
              <label style={labelStyle}>Primary color</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.primary_color}
                onChange={(e) =>
                  updateBrandingField("primary_color", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Accent color</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.accent_color}
                onChange={(e) =>
                  updateBrandingField("accent_color", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Stamp label</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.stamp_label}
                onChange={(e) =>
                  updateBrandingField("stamp_label", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Support email</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.support_email}
                onChange={(e) =>
                  updateBrandingField("support_email", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Website URL</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.website_url}
                onChange={(e) =>
                  updateBrandingField("website_url", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>From name</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.from_name}
                onChange={(e) =>
                  updateBrandingField("from_name", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Reply-to</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.reply_to}
                onChange={(e) =>
                  updateBrandingField("reply_to", e.target.value)
                }
              />
            </div>
            <div>
              <label style={labelStyle}>Verification tagline</label>
              <input
                style={{ ...inputStyle, width: "100%" }}
                value={brandingForm.verification_tagline}
                onChange={(e) =>
                  updateBrandingField("verification_tagline", e.target.value)
                }
              />
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <label style={labelStyle}>Email footer</label>
            <textarea
              style={{
                ...inputStyle,
                width: "100%",
                minHeight: 90,
                resize: "vertical",
              }}
              value={brandingForm.email_footer}
              onChange={(e) =>
                updateBrandingField("email_footer", e.target.value)
              }
            />
          </div>

          <div style={{ marginTop: 14 }}>
            <label style={labelStyle}>Watermark text</label>
            <input
              style={{ ...inputStyle, width: "100%" }}
              value={brandingForm.watermark_text}
              onChange={(e) =>
                updateBrandingField("watermark_text", e.target.value)
              }
            />
          </div>

          <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button style={buttonStyle} onClick={saveBranding}>
              Save branding
            </button>
          </div>

          <div
            style={{
              marginTop: 20,
              padding: 16,
              borderRadius: 12,
              border: "1px solid #dbe4f0",
              background: "#f8fafc",
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 8 }}>
              Email delivery status
            </div>
            <div><strong>Provider:</strong> {emailSettings.provider || "resend"}</div>
            <div><strong>Last status:</strong> {emailSettings.last_delivery_status || "idle"}</div>
            <div><strong>Reply-to:</strong> {emailSettings.reply_to || "—"}</div>
            <div><strong>Last sent:</strong> {fmtDate(emailSettings.last_sent_at)}</div>
            <div><strong>Last test:</strong> {fmtDate(emailSettings.last_test_sent_at)}</div>
          </div>
        </section>
 </>
)}

{activeTab === "email" && (
  <>
<section style={cardStyle}>
  <h2 style={sectionTitle}>Branded Email Sharing</h2>

  {!planMeta?.features?.serverSideEmailSharing && (
    <div
      style={{
        marginBottom: 14,
        padding: 12,
        borderRadius: 10,
        background: "#fffbeb",
        border: "1px solid #fde68a",
        color: "#92400e",
      }}
    >
      Server-side branded email sending is available on Pro and Business.
    </div>
  )}

  <div
    style={{
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 18,
      marginBottom: 18,
    }}
  >
    <div>
      <label style={labelStyle}>Choose stamped audit row</label>
      <select
        style={{ ...inputStyle, width: "100%" }}
        value={selectedAuditForShare}
        onChange={(e) => chooseAuditForShare(e.target.value)}
      >
        <option value="">Choose a stamped record</option>
        {shareableAudits.map((row) => {
          const code =
            row?.verification_code ||
            row?.meta?.verifyCode ||
            row?.meta?.verification_code ||
            row?.verification?.payload?.verify_code ||
            "";
          return (
            <option key={String(row._id)} value={String(row._id)}>
              {row.action || "stamp"} • {code || row._id}
            </option>
          );
        })}
      </select>

      {selectedAuditRecord && (
        <div
          style={{
            marginTop: 14,
            padding: 14,
            borderRadius: 12,
            background: "#f8fafc",
            border: "1px solid #dbe4f0",
          }}
        >
          <div>
            <strong>Verification code:</strong>{" "}
            {selectedAuditRecord?.verification_code ||
              selectedAuditRecord?.meta?.verifyCode ||
              selectedAuditRecord?.meta?.verification_code ||
              selectedAuditRecord?.verification?.payload?.verify_code ||
              "—"}
          </div>
          <div style={{ marginTop: 8 }}>
            <strong>Subject preview:</strong>{" "}
            {shareTemplate?.subject || "—"}
          </div>
        </div>
      )}
    </div>

    <div>
      <label style={labelStyle}>Recipients (To)</label>
      <input
        style={{ ...inputStyle, width: "100%", marginBottom: 10 }}
        value={shareForm.to}
        onChange={(e) =>
          setShareForm((prev) => ({ ...prev, to: e.target.value }))
        }
        placeholder="recipient@example.com, second@example.com"
      />

      <label style={labelStyle}>CC</label>
      <input
        style={{ ...inputStyle, width: "100%", marginBottom: 10 }}
        value={shareForm.cc}
        onChange={(e) =>
          setShareForm((prev) => ({ ...prev, cc: e.target.value }))
        }
        placeholder="Optional"
      />

      <label style={labelStyle}>BCC</label>
      <input
        style={{ ...inputStyle, width: "100%", marginBottom: 10 }}
        value={shareForm.bcc}
        onChange={(e) =>
          setShareForm((prev) => ({ ...prev, bcc: e.target.value }))
        }
        placeholder="Optional"
      />
    </div>
  </div>

  <div style={{ marginBottom: 14 }}>
    <label style={labelStyle}>Subject</label>
    <input
      style={{ ...inputStyle, width: "100%" }}
      value={shareForm.subject}
      onChange={(e) =>
        setShareForm((prev) => ({ ...prev, subject: e.target.value }))
      }
    />
  </div>

  <div style={{ marginBottom: 14 }}>
    <label style={labelStyle}>Optional note</label>
    <textarea
      style={{
        ...inputStyle,
        width: "100%",
        minHeight: 90,
        resize: "vertical",
      }}
      value={shareForm.note}
      onChange={(e) =>
        setShareForm((prev) => ({ ...prev, note: e.target.value }))
      }
    />
  </div>

  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 18 }}>
    <button
      style={buttonStyle}
      onClick={() => {
        if (!planMeta?.features?.serverSideEmailSharing) {
          openUpgradeModal("pro_email");
          return;
        }
        sendShareEmail();
      }}
      disabled={shareSending}
    >
      {shareSending ? "Sending..." : "Send branded email"}
    </button>

    <button
      style={buttonSecondary}
      onClick={() => {
        if (!planMeta?.features?.serverSideEmailSharing) {
          openUpgradeModal("pro_email");
          return;
        }
        sendTestEmail();
      }}
      disabled={shareSending}
    >
      Send test email
    </button>
  </div>

  <div
    style={{
      padding: 16,
      borderRadius: 12,
      border: "1px solid #dbe4f0",
      background: "#ffffff",
    }}
  >
    <div style={{ fontWeight: 700, marginBottom: 12 }}>
      Recent deliveries
    </div>

    {deliveryLoading ? (
      <div>Loading deliveries...</div>
    ) : deliveries.length ? (
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={thStyle}>Created</th>
              <th style={thStyle}>To</th>
              <th style={thStyle}>Subject</th>
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Verification</th>
              <th style={thStyle}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((row) => (
              <tr key={String(row._id)}>
                <td style={tdStyle}>{fmtDeliveryDate(row)}</td>
                <td style={tdStyle}>{(row.to || []).join(", ") || "—"}</td>
                <td style={tdStyle}>{row.subject || "—"}</td>
                <td style={tdStyle}>{row.status || "—"}</td>
                <td style={tdStyle}>{row.verification_code || "—"}</td>
                <td style={tdStyle}>
                  <button
                    style={buttonSecondary}
                    disabled={resendingDeliveryId === String(row._id)}
                    onClick={() => resendDelivery(row._id)}
                  >
                    {resendingDeliveryId === String(row._id)
                      ? "Resending..."
                      : "Resend"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <div>No deliveries yet.</div>
    )}
  </div>
</section>
 </>
)}

{activeTab === "team" && (
  <>
        <section style={cardStyle}>
          <h2 style={sectionTitle}>Team</h2>

          {!canUseTeam && (
            <div
              style={{
                marginBottom: 14,
                padding: 12,
                borderRadius: 10,
                background: "#fffbeb",
                border: "1px solid #fde68a",
                color: "#92400e",
              }}
            >
              Team management is available on Business.
            </div>
          )}

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              alignItems: "end",
              marginBottom: 16,
            }}
          >
            <div>
              <label style={labelStyle}>Invite email</label>
              <input
                style={inputStyle}
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
            </div>
            <div>
              <label style={labelStyle}>Role</label>
              <select
                style={inputStyle}
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="verifier">Verifier</option>
              </select>
            </div>
            <button
              style={buttonStyle}
              onClick={() => {
                if (!canUseTeam) {
                  openUpgradeModal("business_team");
                  return;
                }
                inviteTeammate();
              }}
            >
              Invite teammate
            </button>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={thStyle}>Email</th>
                  <th style={thStyle}>Role</th>
                  <th style={thStyle}>Pending</th>
                  <th style={thStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {team.map((member) => {
                  const busy = teamBusyId === String(member._id);
                  return (
                    <tr key={String(member._id)}>
                      <td style={tdStyle}>{member.email}</td>
                      <td style={tdStyle}>
                        <select
                          style={inputStyle}
                          value={member.role || "user"}
                          disabled={busy}
                          onChange={(e) =>
                            changeTeamRole(member._id, e.target.value)
                          }
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                          <option value="verifier">Verifier</option>
                          {String(member.role || "").toLowerCase() === "owner" && (
                            <option value="owner">Owner</option>
                          )}
                        </select>
                      </td>
                      <td style={tdStyle}>
                        {member.invite_pending ? "Yes" : "No"}
                      </td>
                      <td style={tdStyle}>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          {member.invite_pending && (
                            <>
                              <button
                                style={buttonSecondary}
                                disabled={busy}
                                onClick={() => resendInvite(member._id)}
                              >
                                Resend
                              </button>
                              <button
                                style={buttonSecondary}
                                disabled={busy}
                                onClick={() => cancelInvite(member._id)}
                              >
                                Cancel
                              </button>
                            </>
                          )}

                          {String(member.role || "").toLowerCase() !== "owner" && (
                            <button
                              style={buttonSecondary}
                              disabled={busy}
                              onClick={() =>
                                removeTeammate(member._id, member.email)
                              }
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {!team.length && (
                  <tr>
                    <td style={tdStyle} colSpan={4}>
                      No teammates yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>API Keys</h2>

          {!canUseApi && (
            <div
              style={{
                marginBottom: 14,
                padding: 12,
                borderRadius: 10,
                background: "#fffbeb",
                border: "1px solid #fde68a",
                color: "#92400e",
              }}
            >
              API access is available on Business.
            </div>
          )}

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              alignItems: "end",
              marginBottom: 16,
            }}
          >
            <div>
              <label style={labelStyle}>Key name</label>
              <input
                style={inputStyle}
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
            </div>
            <button
              style={buttonStyle}
              onClick={() => {
                if (!canUseApi) {
                  openUpgradeModal("business_api");
                  return;
                }
                createApiKey();
              }}
            >
              Create API key
            </button>
          </div>

          {newKey && (
            <div
              style={{
                marginBottom: 16,
                padding: 14,
                borderRadius: 12,
                background: "#eff6ff",
                border: "1px solid #bfdbfe",
                color: "#1e3a8a",
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: 6 }}>
                Copy this key now
              </div>
              <div
                style={{
                  wordBreak: "break-all",
                  marginBottom: 10,
                  fontFamily: "monospace",
                }}
              >
                {newKey}
              </div>
              <button
                style={buttonSecondary}
                onClick={() => copyToClipboard(newKey, "API key copied.")}
              >
                Copy
              </button>
            </div>
          )}

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={thStyle}>Name</th>
                  <th style={thStyle}>Prefix</th>
                  <th style={thStyle}>Created</th>
                  <th style={thStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((key) => (
                  <tr key={String(key._id || key.id)}>
                    <td style={tdStyle}>{key.name || "Default Key"}</td>
                    <td style={tdStyle}>{key.prefix || "—"}</td>
                    <td style={tdStyle}>{fmtDate(key.created_at || key.createdAt)}</td>
                    <td style={tdStyle}>
                      <button
                        style={buttonSecondary}
                        onClick={() => deleteApiKey(key._id || key.id)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {!apiKeys.length && (
                  <tr>
                    <td style={tdStyle} colSpan={4}>
                      No API keys yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
</>
)}
{activeTab === "analytics" && (
  <>

        {canUseAnalytics && (
  <>
    <section style={cardStyle}>
      <h2 style={sectionTitle}>Email Analytics</h2>
      <EmailAnalyticsPanel currentPlan={currentPlan} />
    </section>

    <section style={cardStyle}>
      <h2 style={sectionTitle}>Analytics Reports</h2>
      <AnalyticsReportsSettings currentPlan={currentPlan} />
      <div style={{ height: 20 }} />
      <AnalyticsReportsHistory currentPlan={currentPlan} />
    </section>
  </>
)}
</>
)}

{activeTab === "audit" && (
  <>
        <section style={cardStyle}>
          <h2 style={sectionTitle}>Verify PDF</h2>

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              alignItems: "center",
              marginBottom: 14,
            }}
          >
            <input
              type="file"
              accept="application/pdf"
              onChange={(e) => setVerifyFile(e.target.files?.[0] || null)}
            />
            <button style={buttonStyle} onClick={verifyPdf}>
              Verify PDF
            </button>
          </div>

          {verifyResult && (
            <div
              style={{
                border: "1px solid #dbe4f0",
                borderRadius: 14,
                padding: 16,
                background: verified ? "#f0fdf4" : "#fef2f2",
              }}
            >
              <div
                style={{
                  fontWeight: 800,
                  color: verified ? "#166534" : "#991b1b",
                  marginBottom: 10,
                }}
              >
                {verified ? "Verified" : "Not verified"}
              </div>

              <div><strong>Tampered:</strong> {String(!!verifyResult?.tampered)}</div>
              <div><strong>Audit id:</strong> {verifyDetails.audit_id || "—"}</div>
              <div><strong>Stamp id:</strong> {verifyDetails.stamp_id || embeddedPayload.stamp_id || "—"}</div>
              <div><strong>Document id:</strong> {verifyDetails.document_id || embeddedPayload.doc_id || "—"}</div>
              <div><strong>Verification code:</strong> {verifyDetails.verification_code || embeddedPayload.verify_code || "—"}</div>
              <div><strong>Timestamp:</strong> {fmtDate(verifyDetails.timestamp || embeddedPayload.ts)}</div>
            </div>
          )}
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Audit Log</h2>
          <div style={{ marginBottom: 12 }}>
            <button style={buttonSecondary} onClick={loadAudit}>
              Load My Audit
            </button>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={thStyle}>Time</th>
                  <th style={thStyle}>Action</th>
                  <th style={thStyle}>OK</th>
                  <th style={thStyle}>Target</th>
                  <th style={thStyle}>Meta</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((row) => (
                  <tr key={String(row._id)}>
                    <td style={tdStyle}>{fmtDate(row.time)}</td>
                    <td style={tdStyle}>{row.action || "—"}</td>
                    <td style={tdStyle}>{String(row.ok)}</td>
                    <td style={tdStyle}>{row.target || row.document_id || "—"}</td>
                    <td style={tdStyle}>
                      <pre
                        style={{
                          margin: 0,
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                          fontFamily: "inherit",
                        }}
                      >
                        {JSON.stringify(row.meta || {}, null, 2)}
                      </pre>
                    </td>
                  </tr>
                ))}
                {!audit.length && (
                  <tr>
                    <td style={tdStyle} colSpan={5}>
                      No audit activity yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
 </>
)}
        <UpgradeModal
          open={upgradeModalOpen}
          featureKey={upgradeFeatureKey}
          onClose={closeUpgradeModal}
          onUpgrade={async (planKey) => {
            closeUpgradeModal();
            await upgradePlan(
              planKey ||
                (currentPlan === "free" ? getUpgradeTargetPlan() : "business")
            );
          }}
          currentPlan={currentPlan}
        />
      </div>
    </div>
  );
}