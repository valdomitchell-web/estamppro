import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
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

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f6f8fb",
        fontFamily: "Arial, sans-serif",
        padding: 24,
        color: "#1f2937",
      }}
    >
      <div style={{ maxWidth: 760, margin: "40px auto" }}>
        <div
          style={{
            background: "#fff",
            border: "1px solid #e5e7eb",
            borderRadius: 16,
            padding: 28,
            boxShadow: "0 4px 14px rgba(0,0,0,0.06)",
          }}
        >
          <h1 style={{ marginTop: 0, marginBottom: 8, fontSize: 38 }}>
            eStamp Pro
          </h1>
          <div style={{ color: "#6b7280", marginBottom: 20 }}>
            Public verification portal
          </div>

          {loading ? (
            <div>Checking verification…</div>
          ) : err ? (
            <>
              <div
                style={{
                  display: "inline-block",
                  padding: "8px 14px",
                  borderRadius: 999,
                  background: "#fee2e2",
                  color: "#991b1b",
                  fontWeight: 700,
                  marginBottom: 20,
                }}
              >
                Not Verified
              </div>
              <div style={{ color: "#991b1b" }}>{err}</div>
            </>
          ) : (
            <>
              <div
                style={{
                  display: "inline-block",
                  padding: "8px 14px",
                  borderRadius: 999,
                  background: verified ? "#dcfce7" : "#fee2e2",
                  color: verified ? "#166534" : "#991b1b",
                  fontWeight: 700,
                  marginBottom: 20,
                }}
              >
                {verified ? "Verified" : "Not Verified"}
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "180px 1fr",
                  gap: "10px 14px",
                }}
              >
                <div style={{ fontWeight: 700 }}>Verification Code</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>{code}</div>

                <div style={{ fontWeight: 700 }}>Stamp ID</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>
                  {String(details.stamp_id || "—")}
                </div>

                <div style={{ fontWeight: 700 }}>Document ID</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>
                  {String(details.document_id || "—")}
                </div>

                <div style={{ fontWeight: 700 }}>Timestamp</div>
                <div>{details.timestamp ? new Date(details.timestamp).toLocaleString() : "—"}</div>

                <div style={{ fontWeight: 700 }}>Status</div>
                <div>{verified ? "Matching stamp record found." : "Not verified."}</div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}