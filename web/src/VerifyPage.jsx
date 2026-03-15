import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "./api";

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
        setResult(r.data);
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

  const pageStyle = {
    minHeight: "100vh",
    background: "linear-gradient(180deg, #f5f8fc 0%, #eef3f9 100%)",
    fontFamily: "Arial, sans-serif",
    padding: 24,
    color: "#1f2937",
  };

  const wrapStyle = {
    maxWidth: 860,
    margin: "40px auto",
  };

  const cardStyle = {
    background: "#ffffff",
    border: "1px solid #dbe4f0",
    borderRadius: 18,
    padding: 30,
    boxShadow: "0 10px 30px rgba(15, 23, 42, 0.08)",
  };

  const badgeStyle = {
    display: "inline-block",
    padding: "9px 16px",
    borderRadius: 999,
    fontWeight: 700,
    fontSize: 14,
    background: verified ? "#dcfce7" : "#fee2e2",
    color: verified ? "#166534" : "#991b1b",
    marginBottom: 20,
  };

  const statGrid = {
    display: "grid",
    gridTemplateColumns: "220px 1fr",
    gap: "12px 16px",
    marginTop: 18,
  };

  const labelStyle = {
    fontWeight: 700,
    color: "#334155",
  };

  const valueStyle = {
    color: "#111827",
    wordBreak: "break-word",
  };

  const monoStyle = {
    ...valueStyle,
    fontFamily: "Consolas, monospace",
    fontSize: 14,
  };

  const topBarStyle = {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 18,
  };

  const brandStyle = {
    display: "flex",
    flexDirection: "column",
    gap: 4,
  };

  const summaryCard = {
    marginTop: 24,
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: 12,
    padding: 18,
  };

  const footerStyle = {
    marginTop: 24,
    fontSize: 13,
    color: "#64748b",
  };

  return (
    <div style={pageStyle}>
      <div style={wrapStyle}>
        <div style={cardStyle}>
          <div style={topBarStyle}>
            <div style={brandStyle}>
              <h1 style={{ margin: 0, fontSize: 38, color: "#0f172a" }}>eStamp Pro</h1>
              <div style={{ color: "#64748b", fontSize: 15 }}>
                Public verification portal
              </div>
            </div>

            <Link
              to="/"
              style={{
                textDecoration: "none",
                background: "#eff6ff",
                color: "#1d4ed8",
                border: "1px solid #bfdbfe",
                borderRadius: 10,
                padding: "10px 14px",
                fontWeight: 700,
              }}
            >
              Back to dashboard
            </Link>
          </div>

          {loading ? (
            <div
              style={{
                padding: "30px 0",
                fontSize: 18,
                color: "#475569",
              }}
            >
              Checking verification…
            </div>
          ) : err ? (
            <>
              <div style={badgeStyle}>Not Verified</div>
              <div
                style={{
                  background: "#fef2f2",
                  border: "1px solid #fecaca",
                  color: "#991b1b",
                  borderRadius: 12,
                  padding: 16,
                }}
              >
                {err}
              </div>

              <div style={summaryCard}>
                <div style={{ fontWeight: 700, marginBottom: 8 }}>Verification Code</div>
                <div style={monoStyle}>{code || "—"}</div>
              </div>
            </>
          ) : (
            <>
              <div style={badgeStyle}>{verified ? "Verified" : "Not Verified"}</div>

              <div
                style={{
                  background: verified ? "#f0fdf4" : "#fff7ed",
                  border: `1px solid ${verified ? "#bbf7d0" : "#fed7aa"}`,
                  color: verified ? "#166534" : "#9a3412",
                  borderRadius: 12,
                  padding: 16,
                  fontWeight: 600,
                  marginBottom: 18,
                }}
              >
                {verified
                  ? "This document matches an eStamp Pro verification record."
                  : "This document could not be verified."}
              </div>

              <div style={statGrid}>
                <div style={labelStyle}>Verification Code</div>
                <div style={monoStyle}>{code || payload?.verify_code || "—"}</div>

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

                <div style={labelStyle}>Page</div>
                <div style={valueStyle}>{payload?.page ?? details?.page ?? "—"}</div>

                <div style={labelStyle}>Position</div>
                <div style={valueStyle}>
                  X: {payload?.x ?? details?.x ?? "—"} | Y: {payload?.y ?? details?.y ?? "—"}
                </div>

                <div style={labelStyle}>Scale / Opacity</div>
                <div style={valueStyle}>
                  {payload?.scale ?? details?.scale ?? "—"} / {payload?.opacity ?? details?.opacity ?? "—"}
                </div>
              </div>

              <div style={summaryCard}>
                <div
                  style={{
                    fontWeight: 700,
                    marginBottom: 10,
                    color: "#0f172a",
                  }}
                >
                  Verification Summary
                </div>

                <div style={{ color: "#475569", lineHeight: 1.6 }}>
                  This verification record was generated by eStamp Pro. The code shown above
                  matches the stamp metadata and audit trail associated with this document.
                </div>

                {payload?.verify_url && (
                  <div style={{ marginTop: 12 }}>
                    <span style={{ fontWeight: 700, color: "#334155" }}>Verification URL: </span>
                    <span style={monoStyle}>{payload.verify_url}</span>
                  </div>
                )}
              </div>
            </>
          )}

          <div style={footerStyle}>
            eStamp Pro public verification helps confirm whether a stamped document matches a recorded verification entry.
          </div>
        </div>
      </div>
    </div>
  );
}