import React, { useEffect, useMemo, useRef, useState } from "react";
import api from "./api";
import StampDesigner from "./StampDesigner.jsx";
import { Document as PdfDocument, Page, pdfjs } from "react-pdf";
import "react-pdf/dist/Page/AnnotationLayer.css";
import "react-pdf/dist/Page/TextLayer.css";

pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

export default function App() {
  const [email, setEmail] = useState("valdomitchell@gmail.com");
  const [password, setPassword] = useState("");
  const [me, setMe] = useState(null);
  const [err, setErr] = useState("");

  const [file, setFile] = useState(null);
  const [lastDocId, setLastDocId] = useState(null);

  const [bulkFiles, setBulkFiles] = useState([]);
  const [bulkDocumentIds, setBulkDocumentIds] = useState([]);
  const [bulkResults, setBulkResults] = useState([]);

  const [previewPdfFile, setPreviewPdfFile] = useState(null);
  const [previewPageCount, setPreviewPageCount] = useState(0);
  const [previewLoaded, setPreviewLoaded] = useState(false);

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
  const [team, setTeam] = useState([]);
  const [orgName, setOrgName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("user");

  const [apiKeys, setApiKeys] = useState([]);
  const [newKey, setNewKey] = useState(null);

  const pageRef = useRef(null);
  const boxRef = useRef(null);

  const clearErr = () => setErr("");

  const showErr = (e) => {
  console.error(e);
  const raw =
    e?.response?.data?.detail ||
    e?.response?.data?.error ||
    e?.message ||
    "Unknown error";

  const msg =
    String(raw).toLowerCase() === "failed to fetch"
      ? "Download could not be fetched directly. Opening file in browser instead."
      : raw;

  setErr(String(msg));
};

  const selectedStampObj = useMemo(
    () => stamps.find((s) => String(s._id || s.id) === String(selectedStamp)) || null,
    [stamps, selectedStamp]
  );

  const baseStampWidth = Number(selectedStampObj?.width || 160);
  const baseStampHeight = Number(selectedStampObj?.height || 80);

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

  const previewBoxWidth = Math.max(36, Math.round(baseStampWidth * appliedScale));
  const previewBoxHeight = Math.max(22, Math.round(baseStampHeight * appliedScale));

  const clampPreviewToBounds = (x, y, pageWidth, pageHeight) => {
    const maxX = Math.max(0, pageWidth - previewBoxWidth);
    const maxY = Math.max(0, pageHeight - previewBoxHeight);
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
      pageRect.height - ((Number(stampY) || 0) * scaleY) - previewBoxHeight;

    const clamped = clampPreviewToBounds(rawX, rawY, pageRect.width, pageRect.height);
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

    // Same-origin downloads can safely use fetch + blob
    if (target.origin === window.location.origin || url.startsWith(api.defaults.baseURL)) {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error(`Download failed: ${res.status}`);
      const blob = await res.blob();
      downloadBlobFile(blob, filename);
      return;
    }

    // Cross-origin signed URLs: let the browser open/download directly
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.target = "_blank";
    a.rel = "noreferrer";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } catch (err) {
    // last fallback
    window.open(url, "_blank", "noopener,noreferrer");
  }
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
    if (!me) return;
    loadOrg();
    loadTeam();
    loadApiKeys();
    loadStamps();
  }, [me]);

  useEffect(() => {
    if (!file && bulkFiles.length > 0) {
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

  const handlePreviewPointerDown = (e) => {
    if (!pageRef.current || !boxRef.current) return;
    if (!boxRef.current.contains(e.target)) return;

    e.preventDefault();

    const pageRect = pageRef.current.getBoundingClientRect();
    const boxRect = boxRef.current.getBoundingClientRect();

    const startClientX = e.clientX ?? (e.touches?.[0]?.clientX || 0);
    const startClientY = e.clientY ?? (e.touches?.[0]?.clientY || 0);

    const offsetX = startClientX - boxRect.left;
    const offsetY = startClientY - boxRect.top;

    const onMove = (ev) => {
      const clientX = ev.clientX ?? (ev.touches?.[0]?.clientX || 0);
      const clientY = ev.clientY ?? (ev.touches?.[0]?.clientY || 0);

      let x = clientX - pageRect.left - offsetX;
      let y = clientY - pageRect.top - offsetY;

      const clamped = clampPreviewToBounds(x, y, pageRect.width, pageRect.height);
      x = clamped.x;
      y = clamped.y;

      setDragX(x);
      setDragY(y);

      const scaleX = pdfPageWidth / pageRect.width;
      const scaleY = pdfPageHeight / pageRect.height;

      const pdfX = Math.round(x * scaleX);
      const pdfY = Math.round((pageRect.height - y - previewBoxHeight) * scaleY);

      setStampX(pdfX);
      setStampY(pdfY);
    };

    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("touchmove", onMove);
      window.removeEventListener("touchend", onUp);
    };

    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onUp, { passive: false });
    window.addEventListener("touchmove", onMove, { passive: false });
    window.addEventListener("touchend", onUp, { passive: false });
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
  };

  const upgradePlan = async () => {
    clearErr();
    try {
      const r = await api.post("/billing/checkout");
      if (r?.data?.url) {
        window.location.href = r.data.url;
      } else {
        throw new Error("No checkout URL returned");
      }
    } catch (e) {
      showErr(e);
    }
  };

  const loadStamps = async () => {
    clearErr();
    try {
      const r = await api.get("/stamps");
      setStamps(r.data?.stamps || []);
    } catch (e) {
      showErr(e);
    }
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
      alert(`Uploaded document id: ${docId || "unknown"}`);
      await loadAudit();
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
    } catch (e) {
      showErr(e);
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
      alert(`Uploaded ${ids.length} documents for bulk stamping.`);
    } catch (e) {
      showErr(e);
    }
  };

  const useFirstBulkFileForPreview = () => {
    if (!bulkFiles.length) return alert("No bulk PDF selected.");
    setPreviewPdfFile(bulkFiles[0]);
    setPreviewLoaded(false);
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

  const loadAudit = async () => {
    clearErr();
    try {
      const r = await api.get("/audit/my", { params: { limit: 50 } });
      setAudit(r.data?.items || []);
    } catch (e) {
      showErr(e);
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

  const createOrg = async () => {
    if (!orgName.trim()) return alert("Enter organization name");
    clearErr();
    try {
      const r = await api.post("/orgs", { name: orgName });
      setOrgInfo(r.data?.organization || null);
      setOrgName("");
      await loadTeam();
    } catch (e) {
      showErr(e);
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

  const loadApiKeys = async () => {
    try {
      const r = await api.get("/apikeys");
      setApiKeys(r.data?.keys || []);
    } catch (e) {
      if (e?.response?.status !== 404 && e?.response?.status !== 400) showErr(e);
    }
  };

  const createApiKey = async () => {
    clearErr();
    try {
      const r = await api.post("/apikeys", { name: "Default Key" });
      setNewKey(r.data?.rawKey || null);
      await loadApiKeys();
    } catch (e) {
      showErr(e);
    }
  };

  const deleteApiKey = async (id) => {
    clearErr();
    try {
      await api.delete(`/apikeys/${id}`);
      await loadApiKeys();
    } catch (e) {
      showErr(e);
    }
  };

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

  const verifyDetails = verifyResult?.details || {};
  const embedded = verifyResult?.embedded || {};
  const embeddedPayload = embedded?.payload || {};
  const verified = !!verifyResult?.verified;

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

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button style={buttonStyle} onClick={upgradePlan}>
              Upgrade Plan
            </button>
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
            {err}
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          <section style={cardStyle}>
            <h2 style={sectionTitle}>Auth</h2>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
              <input
                style={inputStyle}
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <input
                style={inputStyle}
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button style={buttonStyle} onClick={register}>Register</button>
              <button style={buttonStyle} onClick={login}>Login</button>
              <button style={buttonSecondary} onClick={logout}>Logout</button>
            </div>
            <div style={{ marginTop: 14 }}>
              <strong>Logged in as:</strong> {me?.email || "—"}
            </div>
          </section>

          <section style={cardStyle}>
            <h2 style={sectionTitle}>Upload PDF</h2>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="file"
                accept="application/pdf"
                onChange={(e) => {
                  const f = e.target.files?.[0] || null;
                  setFile(f);
                  setBulkFiles([]);
                  setPreviewPdfFile(f);
                  setPreviewLoaded(false);
                }}
              />
              <button style={buttonStyle} onClick={uploadPdf}>Upload</button>
            </div>
            <div style={{ marginTop: 14 }}>
              <strong>Last uploaded document id:</strong> {lastDocId || "—"}
            </div>
          </section>
        </div>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Bulk Stamping</h2>
          <div style={{ marginBottom: 12, color: "#475569" }}>
            Upload multiple PDFs, then apply the selected stamp to all of them using the same settings.
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
            <input
              type="file"
              accept="application/pdf"
              multiple
              onChange={(e) => {
                const files = Array.from(e.target.files || []);
                setBulkFiles(files);
                if (files.length > 0) {
                  setPreviewPdfFile(files[0]);
                  setPreviewLoaded(false);
                }
              }}
            />
            <button style={buttonSecondary} onClick={uploadBulkPdfs}>Upload Bulk PDFs</button>
            <button style={buttonSecondary} onClick={useFirstBulkFileForPreview}>Preview First PDF</button>
            <button style={buttonStyle} onClick={applyBulkStamp}>Apply Stamp to All</button>
            <button style={buttonStyle} onClick={downloadBulkZip}>Download ZIP</button>
          </div>

          <div><strong>Files selected:</strong> {bulkFiles.length}</div>

          {bulkDocumentIds.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <strong>Uploaded bulk documents:</strong>
              <ul>
                {bulkDocumentIds.map((d) => (
                  <li key={d.id}>{d.name} — {d.id}</li>
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
                      <td style={tdStyle}>{r.ok ? "Success" : `Failed: ${r.error || "unknown"}`}</td>
                      <td style={tdStyle}>{r.verifyCode || "—"}</td>
                      <td style={tdStyle}>
                        {r.downloadUrl ? (
                          <a href={r.downloadUrl} target="_blank" rel="noreferrer">Open</a>
                        ) : r.downloadPath ? (
                          <a href={`${api.defaults.baseURL}${r.downloadPath}`} target="_blank" rel="noreferrer">Open</a>
                        ) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

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
              <button style={buttonStyle} onClick={createOrg}>Create Organization</button>
            </div>
          ) : (
            <>
              <div style={{ marginBottom: 10 }}><strong>Name:</strong> {orgInfo.name}</div>
              <div style={{ marginBottom: 10 }}><strong>Slug:</strong> {orgInfo.slug}</div>
              <div style={{ marginBottom: 16 }}><strong>Plan:</strong> {orgInfo.plan}</div>

              <div style={{ fontWeight: 700, marginBottom: 8 }}>Invite teammate</div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
                <input
                  style={inputStyle}
                  placeholder="Teammate email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                />
                <select
                  style={inputStyle}
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                  <option value="verifier">Verifier</option>
                </select>
                <button style={buttonStyle} onClick={inviteTeammate}>Invite</button>
                <button style={buttonSecondary} onClick={loadTeam}>Refresh Team</button>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th style={thStyle}>Email</th>
                      <th style={thStyle}>Role</th>
                      <th style={thStyle}>Invite Pending</th>
                    </tr>
                  </thead>
                  <tbody>
                    {team.length === 0 ? (
                      <tr><td colSpan={3} style={tdStyle}>No team members yet.</td></tr>
                    ) : (
                      team.map((u) => (
                        <tr key={u._id}>
                          <td style={tdStyle}>{u.email}</td>
                          <td style={tdStyle}>{u.role}</td>
                          <td style={tdStyle}>{u.invite_pending ? "Yes" : "No"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>API Keys</h2>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <button style={buttonStyle} onClick={createApiKey}>Generate API Key</button>
            <button style={buttonSecondary} onClick={loadApiKeys}>Refresh Keys</button>
          </div>

          {newKey && (
            <div
              style={{
                marginBottom: 16,
                padding: 14,
                background: "#fff7ed",
                border: "1px solid #fdba74",
                borderRadius: 10,
                color: "#9a3412",
              }}
            >
              <strong>Copy this key now — it will not be shown again:</strong>
              <div style={{ marginTop: 8, fontFamily: "Consolas, monospace", wordBreak: "break-all" }}>
                {newKey}
              </div>
            </div>
          )}

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={thStyle}>Name</th>
                  <th style={thStyle}>Last Used</th>
                  <th style={thStyle}>Created</th>
                  <th style={thStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.length === 0 ? (
                  <tr><td colSpan={4} style={tdStyle}>No API keys yet.</td></tr>
                ) : (
                  apiKeys.map((k) => (
                    <tr key={k._id}>
                      <td style={tdStyle}>{k.name}</td>
                      <td style={tdStyle}>
                        {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}
                      </td>
                      <td style={tdStyle}>
                        {k.created_at ? new Date(k.created_at).toLocaleString() : "—"}
                      </td>
                      <td style={tdStyle}>
                        <button style={buttonSecondary} onClick={() => deleteApiKey(k._id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Stamp Designer</h2>
          <StampDesigner
            onSaved={(stamp) => {
              loadStamps();
              if (stamp?.id) setSelectedStamp(stamp.id);
            }}
          />
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Apply Stamp</h2>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <label style={labelStyle}>Choose stamp</label>
              <select
                style={inputStyle}
                value={selectedStamp}
                onChange={(e) => setSelectedStamp(e.target.value)}
              >
                <option value="">Select stamp…</option>
                {stamps.map((s) => (
                  <option key={s._id || s.id} value={s._id || s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={labelStyle}>Stamp password</label>
              <input
                style={inputStyle}
                type="password"
                placeholder="Stamp password"
                value={stampPassword}
                onChange={(e) => setStampPassword(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>Page</label>
              <input
                style={inputStyle}
                type="number"
                min={0}
                value={stampPage}
                onChange={(e) => {
                  setStampPage(Number(e.target.value) || 0);
                  setPreviewLoaded(false);
                }}
              />
            </div>

            <div>
              <label style={labelStyle}>Scale</label>
              <input
                style={inputStyle}
                type="number"
                step="0.1"
                value={stampScale}
                onChange={(e) => setStampScale(Number(e.target.value) || 1)}
              />
            </div>

            <div>
              <label style={labelStyle}>X</label>
              <input
                style={inputStyle}
                type="number"
                value={stampX}
                onChange={(e) => setStampX(Number(e.target.value) || 0)}
              />
            </div>

            <div>
              <label style={labelStyle}>Y</label>
              <input
                style={inputStyle}
                type="number"
                value={stampY}
                onChange={(e) => setStampY(Number(e.target.value) || 0)}
              />
            </div>

            <div>
              <label style={labelStyle}>Opacity</label>
              <input
                style={inputStyle}
                type="number"
                min={0}
                max={1}
                step="0.1"
                value={stampOpacity}
                onChange={(e) => setStampOpacity(Number(e.target.value) || 1)}
              />
            </div>
          </div>

          <div style={{ marginTop: 12, marginBottom: 12 }}>
            <div style={{ fontWeight: "bold", marginBottom: 4 }}>
              Placement Preview
            </div>

            <div
              ref={pageRef}
              style={{
                position: "relative",
                width: 612,
                minHeight: 792,
                border: "1px solid #ccc",
                background: "#fff",
                overflow: "hidden",
                touchAction: "none",
              }}
            >
              {previewPdfFile ? (
                <PdfDocument
                  file={previewPdfFile}
                  onLoadSuccess={({ numPages }) => setPreviewPageCount(numPages)}
                  onLoadError={(e) => {
                    console.error("PDF preview load error", e);
                    setErr("Could not render PDF preview.");
                  }}
                >
                  <Page
                    pageNumber={(Number(stampPage) || 0) + 1}
                    width={612}
                    renderTextLayer={false}
                    renderAnnotationLayer={false}
                    onRenderSuccess={() => {
                      setPreviewLoaded(true);
                      setTimeout(syncPreviewFromPdfCoords, 0);
                    }}
                  />
                </PdfDocument>
              ) : (
                <div
                  style={{
                    height: 792,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "#64748b",
                  }}
                >
                  Upload a PDF to preview placement
                </div>
              )}

              <div
                ref={boxRef}
                onPointerDown={handlePreviewPointerDown}
                onTouchStart={handlePreviewPointerDown}
                style={{
                  position: "absolute",
                  left: dragX,
                  top: dragY,
                  width: previewBoxWidth,
                  height: previewBoxHeight,
                  border: "2px dashed red",
                  borderRadius: 6,
                  background: "rgba(255,0,0,0.05)",
                  cursor: "move",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                  fontWeight: 600,
                  userSelect: "none",
                  touchAction: "none",
                }}
              >
                Stamp
              </div>
            </div>

            <small style={{ display: "block", marginTop: 4 }}>
              Drag the red box to choose where the stamp will appear. X/Y fields above update automatically.
              {previewPageCount ? ` PDF pages: ${previewPageCount}` : ""}
            </small>
          </div>

          <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button style={buttonSecondary} onClick={loadStamps}>Reload My Stamps</button>
            <button style={buttonStyle} onClick={applyStamp}>Apply Stamp</button>
          </div>

          {applyResult && (
            <pre
              style={{
                background: "#f8fafc",
                padding: 12,
                fontSize: 12,
                borderRadius: 10,
                marginTop: 14,
                overflowX: "auto",
                border: "1px solid #e2e8f0",
              }}
            >
              {JSON.stringify(applyResult, null, 2)}
            </pre>
          )}
        </section>

        <section style={cardStyle}>
          <h2 style={sectionTitle}>Verify Stamped PDF</h2>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input
              type="file"
              accept="application/pdf"
              onChange={(e) => setVerifyFile(e.target.files?.[0] || null)}
            />
            <button style={buttonStyle} onClick={verifyPdf}>Verify PDF</button>
          </div>

          {verifyResult && (
            <div
              style={{
                marginTop: 20,
                padding: 20,
                borderRadius: 12,
                border: "1px solid #dbe4f0",
                background: "#ffffff",
                maxWidth: 760,
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 18,
                  marginBottom: 12,
                  color: verified ? "#166534" : "#991b1b",
                }}
              >
                {verified ? "Verified Document" : "Verification Failed"}
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: "10px 12px" }}>
                <div style={{ fontWeight: 600 }}>Stamp ID</div>
                <div>{String(verifyDetails?.stamp_id || embeddedPayload?.stamp_id || "—")}</div>

                <div style={{ fontWeight: 600 }}>Document ID</div>
                <div>{String(verifyDetails?.document_id || embeddedPayload?.doc_id || "—")}</div>

                <div style={{ fontWeight: 600 }}>Verification Code</div>
                <div>{embeddedPayload?.verify_code || "—"}</div>

                <div style={{ fontWeight: 600 }}>Timestamp</div>
                <div>
                  {verifyDetails?.timestamp
                    ? new Date(verifyDetails.timestamp).toLocaleString()
                    : embeddedPayload?.ts
                    ? new Date(embeddedPayload.ts).toLocaleString()
                    : "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Page</div>
                <div>{embeddedPayload?.page ?? verifyDetails?.page ?? "—"}</div>

                <div style={{ fontWeight: 600 }}>Position</div>
                <div>
                  X: {embeddedPayload?.x ?? verifyDetails?.x ?? "—"} | Y:{" "}
                  {embeddedPayload?.y ?? verifyDetails?.y ?? "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Scale / Opacity</div>
                <div>
                  {embeddedPayload?.scale ?? verifyDetails?.scale ?? "—"} /{" "}
                  {embeddedPayload?.opacity ?? verifyDetails?.opacity ?? "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Source</div>
                <div>{verifyResult?.source || "audit/pdf"}</div>
              </div>
            </div>
          )}
        </section>

        <section style={cardStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h2 style={{ ...sectionTitle, marginBottom: 0 }}>Audit Log</h2>
            <button style={buttonSecondary} onClick={loadAudit}>Load My Audit</button>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff" }}>
              <thead>
                <tr style={{ background: "#f9fafb" }}>
                  <th style={thStyle}>Time</th>
                  <th style={thStyle}>Action</th>
                  <th style={thStyle}>OK</th>
                  <th style={thStyle}>Target</th>
                  <th style={thStyle}>Meta</th>
                </tr>
              </thead>
              <tbody>
                {audit.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: 12, color: "#6b7280" }}>
                      No audit rows yet.
                    </td>
                  </tr>
                ) : (
                  audit.map((it) => (
                    <tr key={it._id} style={{ borderTop: "1px solid #e5e7eb" }}>
                      <td style={tdStyle}>{it.time ? new Date(it.time).toLocaleString() : "—"}</td>
                      <td style={tdStyle}>{it.action ?? "—"}</td>
                      <td style={tdStyle}>{typeof it.ok === "boolean" ? String(it.ok) : (it.ok ?? "—")}</td>
                      <td style={tdStyle}>{it.target?._id || it.document_id || it.target || "—"}</td>
                      <td style={tdStyle}>{it.meta ? JSON.stringify(it.meta) : "{}"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}