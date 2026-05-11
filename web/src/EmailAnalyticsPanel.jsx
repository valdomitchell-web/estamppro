import React, { useEffect, useMemo, useState } from "react";
import api from "./api";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  BarChart,
  Bar,
} from "recharts";

function pct(n) {
  return `${Math.round(Number(n || 0))}%`;
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function metricValue(label, summary) {
  switch (label) {
    case "Sent": return summary.sent || 0;
    case "Delivered": return summary.delivered || 0;
    case "Opened": return summary.opened || 0;
    case "Clicked": return summary.clicked || 0;
    case "Failed": return summary.failed || 0;
    case "Open rate": return pct(summary.open_rate);
    case "Click rate": return pct(summary.click_rate);
    case "Unique opens": return summary.unique_opened || 0;
    case "Unique clicks": return summary.unique_clicked || 0;
    case "Unique open rate": return pct(summary.unique_open_rate);
    case "Unique click rate": return pct(summary.unique_click_rate);
    case "Engagement score": return pct(summary.engagement_score);
    case "Avg opens / email": return summary.avg_opens_per_email ?? 0;
    case "Avg clicks / email": return summary.avg_clicks_per_email ?? 0;
    default: return 0;
  }
}

const cardStyle = {
  background: "#fff",
  border: "1px solid #dbe4f0",
  borderRadius: 16,
  padding: 20,
  boxShadow: "0 2px 10px rgba(0,0,0,0.03)",
};

const buttonStyle = {
  padding: "10px 14px",
  borderRadius: 12,
  border: "1px solid #cbd5e1",
  background: "#fff",
  color: "#0f172a",
  fontWeight: 700,
};

const disabledButtonStyle = {
  ...buttonStyle,
  background: "#f8fafc",
  color: "#94a3b8",
  border: "1px solid #e2e8f0",
  cursor: "not-allowed",
};

export default function EmailAnalyticsPanel({ currentPlan = "free" }) {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [upgradeMsg, setUpgradeMsg] = useState("");

  const normalizedPlan = String(currentPlan || "free").toLowerCase();
  const canExport = normalizedPlan === "pro" || normalizedPlan === "business";

  const applyPayload = (payload) => {
    setData(payload || null);
  };

  const load = async () => {
    setLoading(true);
    setErr("");
    try {
      const r = await api.get(`/verify/share/analytics?days=${days}`);
      applyPayload(r?.data || null);
    } catch (e) {
      setErr(e?.response?.data?.error || e?.message || "Failed to load analytics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [days]);

 useEffect(() => {
  let alive = true;

  const poll = async () => {
    try {
      const r = await api.get("/verify/share/analytics", {
        params: { days },
      });

      if (alive) applyPayload(r?.data || null);
    } catch {}
  };

  const t = setInterval(poll, 15000);

  return () => {
    alive = false;
    clearInterval(t);
  };
}, [days]);

  const summary = data?.summary || {};
  const docs = safeArray(data?.documents);
  const recent = safeArray(data?.recent);
  const timeline = safeArray(data?.timeline);
  const topDocs = safeArray(data?.top_documents);

  const metricLabels = [
    "Sent",
    "Delivered",
    "Opened",
    "Clicked",
    "Failed",
    "Open rate",
    "Click rate",
    "Unique opens",
    "Unique clicks",
    "Unique open rate",
    "Unique click rate",
    "Engagement score",
    "Avg opens / email",
    "Avg clicks / email",
  ];

  const metrics = useMemo(
    () => metricLabels.map((label) => [label, metricValue(label, summary)]),
    [summary]
  );

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

const exportCsv = async () => {
  if (!canExport) {
    setUpgradeMsg("CSV and PDF analytics exports are available on the Pro and Business plans.");
    return;
  }

  setUpgradeMsg("");
  setErr("");

  try {
    const r = await api.get("/analytics/export/csv", {
      responseType: "blob",
      params: { days },
    });

    downloadBlobFile(
      new Blob([r.data], { type: "text/csv" }),
      "analytics.csv"
    );
  } catch (e) {
    setErr(e?.response?.data?.error || e?.message || "CSV export failed");
  }
};

const exportPdf = async () => {
  if (!canExport) {
    setUpgradeMsg("CSV and PDF analytics exports are available on the Pro and Business plans.");
    return;
  }

  setUpgradeMsg("");
  setErr("");

  try {
    const r = await api.get("/analytics/export/pdf", {
      responseType: "blob",
      params: { days },
    });

    downloadBlobFile(
      new Blob([r.data], { type: "application/pdf" }),
      "analytics-report.pdf"
    );
  } catch (e) {
    setErr(e?.response?.data?.error || e?.message || "PDF export failed");
  }
};
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
            <h2 style={{ margin: 0, fontSize: 22 }}>Email analytics Pro</h2>
            <div style={{ color: "#64748b", marginTop: 6 }}>
              Advanced delivery metrics, top documents, and real-time activity.
            </div>
            <div style={{ color: "#64748b", marginTop: 6 }}>
              Current plan: <strong style={{ textTransform: "capitalize" }}>{normalizedPlan}</strong>
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              style={{ padding: "10px 12px", borderRadius: 12, border: "1px solid #cbd5e1" }}
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

            <button onClick={exportCsv} style={canExport ? buttonStyle : disabledButtonStyle}>
              {canExport ? "Export CSV" : "Upgrade to Pro"}
            </button>

            <button onClick={exportPdf} style={canExport ? buttonStyle : disabledButtonStyle}>
              {canExport ? "Export PDF" : "Upgrade to Pro"}
            </button>
          </div>
        </div>

        {upgradeMsg ? (
          <div
            style={{
              marginBottom: 16,
              color: "#92400e",
              background: "#fff7ed",
              border: "1px solid #fed7aa",
              borderRadius: 12,
              padding: "10px 12px",
            }}
          >
            {upgradeMsg}
          </div>
        ) : null}

        {err ? <div style={{ marginBottom: 16, color: "#b91c1c" }}>{err}</div> : null}

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

        <div style={{ ...cardStyle, padding: 16, marginBottom: 18 }}>
          <h3 style={{ marginTop: 0 }}>Activity timeline</h3>
          {!timeline.length ? (
            <div style={{ color: "#64748b" }}>No timeline data yet.</div>
          ) : (
            <div style={{ width: "100%", height: 280 }}>
              <ResponsiveContainer>
                <LineChart data={timeline}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="sent" />
                  <Line type="monotone" dataKey="opened" />
                  <Line type="monotone" dataKey="clicked" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 18, marginBottom: 18 }}>
          <div style={{ border: "1px solid #e2e8f0", borderRadius: 14, padding: 16 }}>
            <h3 style={{ marginTop: 0 }}>Per-document engagement</h3>
            {!docs.length ? (
              <div style={{ color: "#64748b" }}>No tracked document activity yet.</div>
            ) : (
              docs.slice(0, 10).map((row, idx) => (
                <div
                  key={row.code || idx}
                  style={{ borderTop: "1px solid #e2e8f0", paddingTop: 12, marginTop: 12 }}
                >
                  <div style={{ fontWeight: 700 }}>{row.subject || row.code || "Verification email"}</div>
                  <div style={{ color: "#64748b", marginTop: 4 }}>Code: {row.code || "—"}</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 8 }}>
                    <span>Sent: {row.sent ?? 0}</span>
                    <span>Delivered: {row.delivered ?? 0}</span>
                    <span>Opened: {row.opened ?? 0}</span>
                    <span>Clicked: {row.clicked ?? 0}</span>
                    <span>Total opens: {row.total_opens ?? 0}</span>
                    <span>Total clicks: {row.total_clicks ?? 0}</span>
                    <span>Unique opens: {row.unique_opened ?? 0}</span>
                    <span>Unique clicks: {row.unique_clicked ?? 0}</span>
                    <span>Score: {row.score ?? 0}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          <div style={{ border: "1px solid #e2e8f0", borderRadius: 14, padding: 16 }}>
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
                    <span>Opens: {row.opens ?? 0}</span>
                    <span>Clicks: {row.clicks ?? 0}</span>
                    <span>Code: {row.code ?? "—"}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
          <div style={{ border: "1px solid #e2e8f0", borderRadius: 14, padding: 16 }}>
            <h3 style={{ marginTop: 0 }}>Top performing documents</h3>
            {!topDocs.length ? (
              <div style={{ color: "#64748b" }}>No ranked documents yet.</div>
            ) : (
              <div style={{ width: "100%", height: 280 }}>
                <ResponsiveContainer>
                  <BarChart data={topDocs}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="code" />
                    <YAxis allowDecimals={false} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="opened" />
                    <Bar dataKey="clicked" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          <div style={{ border: "1px solid #e2e8f0", borderRadius: 14, padding: 16 }}>
            <h3 style={{ marginTop: 0 }}>Live insights</h3>
            <ul style={{ margin: 0, paddingLeft: 18, color: "#334155", lineHeight: 1.8 }}>
              <li>Unique opens track distinct recipients who opened at least once.</li>
              <li>Unique clicks track distinct recipients who clicked at least once.</li>
              <li>Engagement score weights clicks higher than opens.</li>
              <li>The timeline updates automatically while this page stays open.</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}