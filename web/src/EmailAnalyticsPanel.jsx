import React, { useEffect, useMemo, useState } from "react";
import api from "./api";

function pct(n) {
  return `${Math.round(Number(n || 0))}%`;
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

const cardStyle = {
  background: "#fff",
  border: "1px solid #dbe4f0",
  borderRadius: 16,
  padding: 20,
  boxShadow: "0 2px 10px rgba(0,0,0,0.03)",
};

export default function EmailAnalyticsPanel() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = async () => {
    setLoading(true);
    setErr("");
    try {
      const r = await api.get(`/verify/share/analytics?days=${days}`);
      setData(r?.data || null);
    } catch (e) {
      setErr(e?.response?.data?.error || e?.message || "Failed to load analytics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [days]);

  const summary = data?.summary || {};
  const docs = safeArray(data?.documents);
  const recent = safeArray(data?.recent);

  const metrics = useMemo(
    () => [
      ["Sent", summary.sent || 0],
      ["Delivered", summary.delivered || 0],
      ["Opened", summary.opened || 0],
      ["Clicked", summary.clicked || 0],
      ["Failed", summary.failed || 0],
      ["Open rate", pct(summary.open_rate)],
      ["Click rate", pct(summary.click_rate)],
    ],
    [summary]
  );

  return (
    <section style={{ marginTop: 28 }}>
      <div style={cardStyle}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 16,
            alignItems: "center",
            marginBottom: 18,
            flexWrap: "wrap",
          }}
        >
          <div>
            <h2 style={{ margin: 0, fontSize: 22 }}>Email analytics</h2>
            <div style={{ color: "#64748b", marginTop: 6 }}>
              Open tracking, click tracking, and document engagement.
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              style={{
                padding: "10px 12px",
                borderRadius: 12,
                border: "1px solid #cbd5e1",
              }}
            >
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>

            <button
              onClick={load}
              style={{
                padding: "10px 14px",
                borderRadius: 12,
                border: "1px solid #93c5fd",
                background: "#eff6ff",
                color: "#1d4ed8",
                fontWeight: 700,
              }}
            >
              {loading ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {err ? (
          <div style={{ marginBottom: 16, color: "#b91c1c" }}>{err}</div>
        ) : null}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: 12,
            marginBottom: 20,
          }}
        >
          {metrics.map(([label, value]) => (
            <div
              key={label}
              style={{
                border: "1px solid #e2e8f0",
                borderRadius: 14,
                padding: 14,
                background: "#f8fafc",
              }}
            >
              <div style={{ color: "#64748b", fontSize: 13 }}>{label}</div>
              <div style={{ fontSize: 26, fontWeight: 800, marginTop: 6 }}>
                {value}
              </div>
            </div>
          ))}
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.2fr 1fr",
            gap: 18,
          }}
        >
          <div
            style={{
              border: "1px solid #e2e8f0",
              borderRadius: 14,
              padding: 16,
            }}
          >
            <h3 style={{ marginTop: 0 }}>Per-document engagement</h3>

            {!docs.length ? (
              <div style={{ color: "#64748b" }}>No tracked document activity yet.</div>
            ) : (
              docs.slice(0, 10).map((row, idx) => (
                <div
                  key={row.code || row.verification_code || idx}
                  style={{ borderTop: "1px solid #e2e8f0", paddingTop: 12, marginTop: 12 }}
                >
                  <div style={{ fontWeight: 700 }}>
                    {row.subject || row.code || row.verification_code || "Verification email"}
                  </div>
                  <div style={{ color: "#64748b", marginTop: 4 }}>
                    Code: {row.code || row.verification_code || "—"}
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 8 }}>
                    <span>Sent: {row.sent ?? row.emails_sent ?? 0}</span>
                    <span>Opened: {row.opened ?? 0}</span>
                    <span>Clicked: {row.clicked ?? 0}</span>
                    <span>Total opens: {row.total_opens ?? 0}</span>
                    <span>Total clicks: {row.total_clicks ?? 0}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          <div
            style={{
              border: "1px solid #e2e8f0",
              borderRadius: 14,
              padding: 16,
            }}
          >
            <h3 style={{ marginTop: 0 }}>Recent tracked activity</h3>

            {!recent.length ? (
              <div style={{ color: "#64748b" }}>No delivery activity yet.</div>
            ) : (
              recent.map((row, idx) => (
                <div
                  key={row._id || `${row.code || "row"}-${idx}`}
                  style={{ borderTop: "1px solid #e2e8f0", paddingTop: 12, marginTop: 12 }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                    <strong>{row.subject || "Verification email"}</strong>
                    <span style={{ textTransform: "capitalize" }}>
                      {row.activity_type || row.status || "Tracked"}
                    </span>
                  </div>

                  <div style={{ color: "#64748b", marginTop: 4 }}>
                    {Array.isArray(row.to) ? row.to.join(", ") : row.to || "—"}
                  </div>

                  <div style={{ marginTop: 8, display: "flex", gap: 12, flexWrap: "wrap" }}>
                    <span>Opens: {row.opens ?? row.open_count ?? 0}</span>
                    <span>Clicks: {row.clicks ?? row.click_count ?? 0}</span>
                    <span>Code: {row.code || row.verification_code || "—"}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </section>
  );
}