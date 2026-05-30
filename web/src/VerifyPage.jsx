import React, { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "./api";

function joinUrl(base, relativePath) {
  if (!relativePath) return "";
  if (/^https?:\/\//i.test(relativePath)) return relativePath;
  return `${String(base || "").replace(/\/$/, "")}${relativePath.startsWith("/") ? "" : "/"}${relativePath}`;
}

export default function VerifyPage() {
  const { code } = useParams();
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get(`/verify/public?code=${encodeURIComponent(code)}`, {
          headers: { Accept: "application/json" },
        });
        setResult(r.data || null);
      } catch (e) {
        const data = e?.response?.data;
        setErr(data?.detail || data?.error || "Verification failed");
      } finally {
        setLoading(false);
      }
    })();
  }, [code]);

  const verified = !!result?.verified;
  const details = result?.details || {};
  const verification = details?.verification || {};
  const payload = verification?.payload || {};
  const branding = result?.branding || {};
  const apiBase = api?.defaults?.baseURL || "";
  const certificateUrl = joinUrl(apiBase, result?.certificate_url);
  const emailTemplateUrl = joinUrl(apiBase, result?.email_template_url);
  const emailPreview = result?.email_preview || {};

  const theme = useMemo(
    () => ({
      primary: branding?.primary_color || "#1d4ed8",
      accent: branding?.accent_color || "#0f172a",
      label: branding?.stamp_label || "Official eStamp",
      orgName: branding?.org_name || "eStamp Pro",
      tagline: branding?.verification_tagline || "Digital verification you can trust",
      footer: branding?.email_footer || "Sent securely by eStamp Pro",
      logo: branding?.logo_url || "",
      supportEmail: branding?.support_email || "",
      websiteUrl: branding?.website_url || "",
      plan: branding?.plan || "free",
    }),
    [branding]
  );

  const isMobile =
  typeof window !== "undefined" && window.innerWidth < 640;

  const pageStyle = {
  minHeight: "100vh",
  background: "linear-gradient(180deg, #f8fbff 0%, #eef4fb 100%)",
  fontFamily: "Arial, sans-serif",
  padding: isMobile ? 8 : 24,
  color: "#1f2937",
  boxSizing: "border-box",
};

const wrapStyle = {
  width: "100%",
  maxWidth: 980,
  margin: isMobile ? "8px auto" : "40px auto",
  boxSizing: "border-box",
};

  const cardStyle = {
    background: "#ffffff",
    border: "1px solid #dbe4f0",
    borderRadius: 22,
    overflow: "hidden",
    boxShadow: "0 10px 30px rgba(15, 23, 42, 0.08)",
  };

  const heroStyle = {
    padding: 28,
    background: theme.primary,
    color: "#ffffff",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 20,
    flexWrap: "wrap",
  };

  const actionBtn = (filled = false) => ({
    textDecoration: "none",
    background: filled ? theme.primary : "#ffffff",
    color: filled ? "#ffffff" : theme.primary,
    border: `1px solid ${theme.primary}`,
    borderRadius: 12,
    padding: "10px 14px",
    fontWeight: 700,
    display: "inline-block",
  });

  const bodyStyle = {
  padding: isMobile ? 16 : 28,
  boxSizing: "border-box",
};

  const badgeStyle = {
    display: "inline-block",
    padding: "9px 16px",
    borderRadius: 999,
    fontWeight: 700,
    fontSize: 14,
    background: verified ? "#dcfce7" : "#fee2e2",
    color: verified ? "#166534" : "#991b1b",
    marginBottom: 18,
  };
  const statusBoxStyle = {
    background: verified ? "#f0fdf4" : "#fef2f2",
    border: `1px solid ${verified ? "#bbf7d0" : "#fecaca"}`,
    color: verified ? "#166534" : "#991b1b",
    borderRadius: 12,
    padding: 16,
    fontWeight: 600,
    marginBottom: 22,
  };
 const gridStyle = {
  display: "grid",
  gridTemplateColumns: isMobile ? "1fr" : "190px 1fr",
  gap: isMobile ? "6px" : "12px 16px",
};
  const labelStyle = { fontWeight: 700, color: "#334155" };

 const valueStyle = {
  color: "#111827",
  minWidth: 0,
  overflowWrap: "anywhere",
  wordBreak: "break-word",
};

 const monoStyle = {
  ...valueStyle,
  fontFamily: "Consolas, monospace",
  fontSize: isMobile ? 13 : 14,
  lineHeight: 1.45,
};

const codeStyle = {
  ...monoStyle,
  whiteSpace: "nowrap",
  overflowX: "auto",
};

  const panelStyle = {
    marginTop: 24,
    background: "#f8fafc",
    border: "1px solid #dbe4f0",
    borderRadius: 16,
    padding: 20,
  };

  return (
    <div style={pageStyle}>
      <div style={wrapStyle}>
        <div style={cardStyle}>
          <div style={heroStyle}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              {theme.logo ? (
                <img
                  src={theme.logo}
                  alt={`${theme.orgName} logo`}
                  style={{ width: 72, height: 72, objectFit: "contain", borderRadius: 14, background: "rgba(255,255,255,.12)", padding: 8 }}
                />
              ) : null}
              <div>
               <h1
  style={{
    margin: 0,
    fontSize: isMobile ? 28 : 36,
    lineHeight: 1.1,
    wordBreak: "break-word",
  }}
>
  {theme.orgName}
</h1>
                <div style={{ marginTop: 8, fontSize: 15, opacity: 0.95 }}>{theme.tagline}</div>
                <div style={{ marginTop: 8, fontSize: 13, opacity: 0.9 }}>
                  Plan: <strong>{theme.plan}</strong> · Stamp label: <strong>{theme.label}</strong>
                </div>
              </div>
            </div>

            <Link to="/" style={{ ...actionBtn(false), borderColor: "rgba(255,255,255,.6)", color: "#fff", background: "transparent" }}>
              Back to dashboard
            </Link>
          </div>

          <div style={bodyStyle}>
            {loading ? (
              <div style={{ padding: "30px 0", fontSize: 18, color: "#475569" }}>Checking verification…</div>
            ) : err ? (
              <>
                <div style={badgeStyle}>Not Verified</div>
                <div style={statusBoxStyle}>{err}</div>
                <div style={panelStyle}>
                  <div style={{ fontWeight: 700, marginBottom: 8 }}>Verification Code</div>
                  <div style={monoStyle}>{code || "—"}</div>
                </div>
              </>
            ) : (
              <>
                <div style={badgeStyle}>{verified ? "Verified" : "Not Verified"}</div>

                <div style={statusBoxStyle}>
                  {verified
                    ? `This document matches ${theme.orgName}'s stored verification record.`
                    : "This document could not be verified."}
                </div>

                <div style={gridStyle}>
                  <div style={labelStyle}>Verification Code</div>
                  <div style={codeStyle}>{code || payload?.verify_code || "—"}</div>

                  <div style={labelStyle}>Stamp ID</div>
                  <div style={monoStyle}>{String(details?.stamp_id || payload?.stamp_id || "—")}</div>

                  <div style={labelStyle}>Document ID</div>
                  <div style={monoStyle}>{String(details?.document_id || payload?.doc_id || "—")}</div>

                  <div style={labelStyle}>Timestamp</div>
                  <div style={valueStyle}>
                    {details?.timestamp
                      ? new Date(details.timestamp).toLocaleString()
                      : payload?.ts
                      ? new Date(payload.ts).toLocaleString()
                      : "—"}
                  </div>

                  <div style={labelStyle}>Brand label</div>
                  <div style={valueStyle}>{theme.label}</div>

                  <div style={labelStyle}>Verification URL</div>
                  <div style={monoStyle}>{payload?.verify_url || window.location.href}</div>
                </div>

                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 24 }}>
                  {certificateUrl ? (
                    <a href={certificateUrl} target="_blank" rel="noreferrer" style={actionBtn(true)}>
                      Download certificate
                    </a>
                  ) : null}
                  {emailTemplateUrl ? (
                    <a href={emailTemplateUrl} target="_blank" rel="noreferrer" style={actionBtn(false)}>
                      Open branded email preview
                    </a>
                  ) : null}
                </div>

                <div style={panelStyle}>
                  <div style={{ fontWeight: 700, marginBottom: 10, color: theme.accent }}>Verification Summary</div>
                  <div style={{ color: "#475569", lineHeight: 1.6 }}>
                    This public verification view now uses the issuing organization’s branding, and the same brand kit also powers the downloadable certificate and email template for the record.
                  </div>
                  {(theme.supportEmail || theme.websiteUrl) && (
                    <div style={{ marginTop: 12, color: "#475569" }}>
                      {theme.supportEmail ? <div><strong>Support:</strong> {theme.supportEmail}</div> : null}
                      {theme.websiteUrl ? <div><strong>Website:</strong> {theme.websiteUrl}</div> : null}
                    </div>
                  )}
                </div>

                {emailPreview?.html ? (
                  <div style={panelStyle}>
                    <div style={{ fontWeight: 700, marginBottom: 10, color: theme.accent }}>Email Template Preview</div>
                    <div style={{ marginBottom: 12, color: "#475569" }}>
                      <strong>Subject:</strong> {emailPreview.subject || "—"}
                    </div>
                    <div
  style={{
    border: "1px solid #dbe4f0",
    borderRadius: 14,
    overflowX: "auto",
    background: "#fff",
    width: "100%",
    boxSizing: "border-box",
  }}
>
  <div
    style={{
      minWidth: isMobile ? 520 : "auto",
      maxWidth: "100%",
    }}
    dangerouslySetInnerHTML={{ __html: emailPreview.html }}
  />
</div>
                  </div>
                ) : null}
              </>
            )}

            <div style={{ marginTop: 24, fontSize: 13, color: "#64748b" }}>{theme.footer}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
