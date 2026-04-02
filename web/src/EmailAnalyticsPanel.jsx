import React, { useEffect, useState } from "react";
import axios from "axios";

export default function EmailAnalyticsPanel({ apiBase = "/api" }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const api = axios.create({ baseURL: apiBase, withCredentials: true });

  async function load() {
    try {
      setErr("");
      const res = await api.get("/verify/share/analytics");
      setData(res.data);
    } catch (e) {
      setErr(e?.response?.data?.error || e.message || "Failed to load analytics");
    }
  }

  useEffect(() => { load(); }, []);

  const s = data?.summary || {};
  const docs = data?.documents || [];

  return (
    <section style={{ marginTop: 24, padding: 24, border: "1px solid #dbe4f0", borderRadius: 24, background: "#fff" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Email analytics</h2>
        <button onClick={load}>Refresh</button>
      </div>
      {err ? <div style={{ color: "#b42318", marginBottom: 12 }}>{err}</div> : null}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, minmax(120px, 1fr))", gap: 12, marginBottom: 20 }}>
        {[
          ["Total", s.total || 0],
          ["Sent", s.sent || 0],
          ["Delivered", s.delivered || 0],
          ["Opened", s.opened || 0],
          ["Clicked", s.clicked || 0],
          ["Failed", s.failed || 0],
        ].map(([label, value]) => (
          <div key={label} style={{ padding: 14, borderRadius: 18, border: "1px solid #dbe4f0", background: "#f8fbff" }}>
            <div style={{ fontSize: 14, opacity: 0.75 }}>{label}</div>
            <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(180px, 1fr))", gap: 12, marginBottom: 24 }}>
        <div>Delivery rate: <strong>{Math.round((s.delivery_rate || 0) * 100)}%</strong></div>
        <div>Open rate: <strong>{Math.round((s.open_rate || 0) * 100)}%</strong></div>
        <div>Click rate: <strong>{Math.round((s.click_rate || 0) * 100)}%</strong></div>
      </div>
      <h3 style={{ marginTop: 0 }}>Document engagement</h3>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {['Verification code', 'Emails', 'Opened', 'Clicked', 'Total opens', 'Total clicks', 'Latest status'].map((h) => (
                <th key={h} style={{ textAlign: 'left', padding: '10px 8px', borderBottom: '1px solid #dbe4f0' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {docs.map((row) => (
              <tr key={row.verification_code}>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.verification_code}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.emails_sent}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.opened}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.clicked}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.total_opens}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.total_clicks}</td>
                <td style={{ padding: '10px 8px', borderBottom: '1px solid #eef3f8' }}>{row.latest_status}</td>
              </tr>
            ))}
            {!docs.length ? (
              <tr><td colSpan={7} style={{ padding: 16, opacity: 0.7 }}>No tracked email activity yet.</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
