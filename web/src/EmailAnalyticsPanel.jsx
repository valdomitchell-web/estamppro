import React, { useEffect, useState } from "react";
import api from "./api";

function pct(value) {
  return `${Math.round((Number(value || 0) * 100 + Number.EPSILON) * 10) / 10}%`;
}

export default function EmailAnalyticsPanel() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/verify/share/analytics");
        setData(r.data || null);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.response?.data?.error || e.message || "Failed to load analytics");
      }
    })();
  }, []);

  if (err) return <div style={{ color: "#b91c1c" }}>{err}</div>;
  if (!data) return <div>Loading email analytics…</div>;

  return (
    <div style={{ border: "1px solid #e5e7eb", borderRadius: 12, padding: 16, marginTop: 16 }}>
      <h3 style={{ marginTop: 0 }}>Email Analytics</h3>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 12 }}>
        <div><strong>{data.total}</strong><div>Total</div></div>
        <div><strong>{data.sent}</strong><div>Sent</div></div>
        <div><strong>{data.delivered}</strong><div>Delivered</div></div>
        <div><strong>{data.opened}</strong><div>Opened</div></div>
        <div><strong>{data.failed + data.bounced + data.complained}</strong><div>Failures</div></div>
        <div><strong>{pct(data.open_rate)}</strong><div>Open rate</div></div>
        <div><strong>{pct(data.failure_rate)}</strong><div>Failure rate</div></div>
      </div>

      {Array.isArray(data.recent) && data.recent.length > 0 ? (
        <div style={{ marginTop: 16 }}>
          <h4>Recent email activity</h4>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th align="left">Status</th>
                  <th align="left">Subject</th>
                  <th align="left">Recipient</th>
                  <th align="left">Code</th>
                  <th align="left">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.recent.map((item) => (
                  <tr key={item._id}>
                    <td>{item.status}</td>
                    <td>{item.subject || "—"}</td>
                    <td>{Array.isArray(item.to) ? item.to.join(", ") : "—"}</td>
                    <td>{item.verification_code || "—"}</td>
                    <td>{item.created_at ? new Date(item.created_at).toLocaleString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
