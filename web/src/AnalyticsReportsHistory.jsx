import React, { useEffect, useState } from "react";
import api from "./api";

const cardStyle = {
  background: "#fff",
  border: "1px solid #dbe4f0",
  borderRadius: 16,
  padding: 20,
  boxShadow: "0 2px 10px rgba(0,0,0,0.03)",
};

function fmtDate(value) {
  if (!value) return "—";

  const d = new Date(value);

  if (Number.isNaN(d.getTime())) return "—";

  return (
    d.toLocaleString("en-GB", {
      timeZone: "America/Grenada",
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    }) + " AST"
  );
}

function StatusBadge({ status }) {
  const s = String(status || "").toLowerCase();

  let bg = "#f8fafc";
  let fg = "#334155";
  let bd = "#cbd5e1";

  if (s === "sent") {
    bg = "#f0fdf4";
    fg = "#166534";
    bd = "#bbf7d0";
  } else if (s === "failed") {
    bg = "#fef2f2";
    fg = "#991b1b";
    bd = "#fecaca";
  } else if (s === "skipped") {
    bg = "#fff7ed";
    fg = "#9a3412";
    bd = "#fed7aa";
  } else if (s === "started") {
    bg = "#eff6ff";
    fg = "#1d4ed8";
    bd = "#bfdbfe";
  }

  return (
    <span
      style={{
        display: "inline-block",
        padding: "4px 10px",
        borderRadius: 999,
        border: `1px solid ${bd}`,
        background: bg,
        color: fg,
        fontWeight: 700,
        fontSize: 12,
        textTransform: "capitalize",
      }}
    >
      {s || "unknown"}
    </span>
  );
}

export default function AnalyticsReportsHistory() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function loadHistory() {
  setLoading(true);
  setErr("");

  try {
    const r = await api.get("/orgs/reports/history", {
      params: { t: Date.now() },
      headers: {
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
      },
    });

    setRows(Array.isArray(r?.data?.items) ? r.data.items : []);
  } catch (e) {
    setErr(
      e?.response?.data?.error ||
        e?.message ||
        "Failed to load report history."
    );
  } finally {
    setLoading(false);
  }
}

  useEffect(() => {
    loadHistory();
  }, []);

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
            <h2 style={{ margin: 0, fontSize: 22 }}>Report history</h2>
            <div style={{ color: "#64748b", marginTop: 6 }}>
              Recent manual and scheduled analytics report runs.
            </div>
          </div>

          <button
            onClick={loadHistory}
            style={{
              padding: "10px 14px",
              borderRadius: 12,
              border: "1px solid #93c5fd",
              background: "#eff6ff",
              color: "#1d4ed8",
              fontWeight: 700,
            }}
          >
            {loading ? "Refreshing..." : "Refresh history"}
          </button>
        </div>

        {err ? (
          <div
            style={{
              marginBottom: 14,
              color: "#991b1b",
              background: "#fef2f2",
              border: "1px solid #fecaca",
              borderRadius: 12,
              padding: "10px 12px",
            }}
          >
            {err}
          </div>
        ) : null}

        {!rows.length && !loading ? (
          <div style={{ color: "#64748b" }}>No report runs yet.</div>
        ) : null}

        <div style={{ display: "grid", gap: 12 }}>
          {rows.map((row, idx) => (
            <div
              key={row._id || idx}
              style={{
                border: "1px solid #e2e8f0",
                borderRadius: 14,
                padding: 16,
                background: "#f8fafc",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: 16,
                  alignItems: "center",
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <div style={{ fontWeight: 800, color: "#0f172a" }}>
                    {row.subject || "Weekly Analytics Report"}
                  </div>
                  <div style={{ color: "#64748b", marginTop: 4 }}>
                    {String(row.kind || "scheduled").toUpperCase()} · Started{" "}
                    {fmtDate(row.started_at || row.createdAt)}
                  </div>
                </div>

                <StatusBadge status={row.status} />
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                  gap: 10,
                  marginTop: 14,
                }}
              >
                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>Recipients</div>
                  <div style={{ color: "#0f172a", marginTop: 4 }}>
                    {Array.isArray(row.recipients) && row.recipients.length
                      ? row.recipients.join(", ")
                      : "—"}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>Finished</div>
                  <div style={{ color: "#0f172a", marginTop: 4 }}>
                    {fmtDate(row.finished_at)}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>Range</div>
                  <div style={{ color: "#0f172a", marginTop: 4 }}>
                    {row.range_days || 7} days
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>Reason</div>
                  <div style={{ color: "#0f172a", marginTop: 4 }}>
                    {row.reason || "—"}
                  </div>
                </div>
              </div>

              {row.error_message ? (
                <div
                  style={{
                    marginTop: 14,
                    padding: "10px 12px",
                    borderRadius: 12,
                    border: "1px solid #fecaca",
                    background: "#fef2f2",
                    color: "#991b1b",
                  }}
                >
                  <strong>Error:</strong> {row.error_message}
                </div>
              ) : null}

              {row.meta?.summary ? (
                <div
                  style={{
                    marginTop: 14,
                    padding: "12px 14px",
                    borderRadius: 12,
                    border: "1px solid #dbe4f0",
                    background: "#fff",
                  }}
                >
                  <div style={{ fontWeight: 700, color: "#0f172a", marginBottom: 8 }}>
                    Run summary
                  </div>
                  <div style={{ display: "flex", gap: 14, flexWrap: "wrap", color: "#334155" }}>
                    <span>Sent: {row.meta.summary.sent ?? 0}</span>
                    <span>Opened: {row.meta.summary.opened ?? 0}</span>
                    <span>Clicked: {row.meta.summary.clicked ?? 0}</span>
                    <span>Failed: {row.meta.summary.failed ?? 0}</span>
                    <span>Open rate: {row.meta.summary.open_rate ?? 0}%</span>
                    <span>Click rate: {row.meta.summary.click_rate ?? 0}%</span>
                  </div>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}