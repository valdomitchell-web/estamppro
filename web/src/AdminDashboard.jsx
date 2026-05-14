import React, { useEffect, useMemo, useState } from "react";
import api from "./api";

export default function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [failedActions, setFailedActions] = useState([]);
  const [search, setSearch] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    setErr("");

    try {
      const [s, o, f] = await Promise.all([
        api.get("/admin/overview"),
        api.get("/admin/orgs"),
        api.get("/admin/failed-actions").catch(() => ({ data: { items: [] } })),
      ]);

      setStats(s.data?.stats || null);
      setOrgs(o.data?.orgs || []);
      setFailedActions(f.data?.items || []);
    } catch (e) {
      setErr(e?.response?.data?.error || e?.message || "Failed to load admin dashboard.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filteredOrgs = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return orgs;

    return orgs.filter((o) =>
      [o.name, o.slug, o.plan, o.billing]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [orgs, search]);

  const cardStyle = {
    padding: 18,
    border: "1px solid #dbeafe",
    borderRadius: 16,
    background: "#fff",
    boxShadow: "0 6px 18px rgba(15,23,42,0.05)",
  };

  const metricValue = {
    fontSize: 30,
    fontWeight: 900,
    marginTop: 10,
    color: "#0f172a",
  };

  const thStyle = {
    textAlign: "left",
    padding: "12px 14px",
    borderBottom: "1px solid #e2e8f0",
    color: "#334155",
    fontSize: 14,
  };

  const tdStyle = {
    padding: "12px 14px",
    borderBottom: "1px solid #f1f5f9",
    verticalAlign: "middle",
  };

  const badge = (value) => {
    const v = String(value || "inactive").toLowerCase();

    const styles = {
      active: { bg: "#ecfdf5", fg: "#166534", bd: "#bbf7d0" },
      inactive: { bg: "#f8fafc", fg: "#475569", bd: "#cbd5e1" },
      past_due: { bg: "#fef2f2", fg: "#991b1b", bd: "#fecaca" },
      canceled: { bg: "#fff7ed", fg: "#9a3412", bd: "#fed7aa" },
    };

    const s = styles[v] || styles.inactive;

    return (
      <span
        style={{
          display: "inline-block",
          padding: "5px 10px",
          borderRadius: 999,
          background: s.bg,
          color: s.fg,
          border: `1px solid ${s.bd}`,
          fontWeight: 800,
          fontSize: 12,
          textTransform: "capitalize",
        }}
      >
        {v.replace("_", " ")}
      </span>
    );
  };

  const usageBar = (pct = 0) => {
    const safe = Math.max(0, Math.min(100, Number(pct || 0)));
    const barColor =
      safe >= 100 ? "#b91c1c" : safe >= 80 ? "#d97706" : "#1d4ed8";

    return (
      <div style={{ minWidth: 150 }}>
        <div style={{ fontSize: 13, fontWeight: 800, marginBottom: 5 }}>
          {safe}%
        </div>
        <div
          style={{
            height: 9,
            background: "#e2e8f0",
            borderRadius: 999,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${safe}%`,
              height: "100%",
              background: barColor,
            }}
          />
        </div>
      </div>
    );
  };

  return (
    <div style={{ padding: 20 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 14,
          alignItems: "center",
          marginBottom: 24,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: 30 }}>Admin Dashboard</h2>
          <div style={{ color: "#64748b", marginTop: 6 }}>
            Platform usage, billing health, and organization monitoring.
          </div>
        </div>

        <button
          onClick={load}
          style={{
            padding: "10px 16px",
            borderRadius: 12,
            border: "1px solid #bfdbfe",
            background: "#eff6ff",
            color: "#1d4ed8",
            fontWeight: 800,
            cursor: "pointer",
          }}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {err && (
        <div
          style={{
            marginBottom: 18,
            padding: 12,
            borderRadius: 12,
            background: "#fef2f2",
            border: "1px solid #fecaca",
            color: "#991b1b",
            fontWeight: 700,
          }}
        >
          {err}
        </div>
      )}

      {stats && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
            gap: 16,
            marginBottom: 28,
          }}
        >
          <div style={cardStyle}>
            <h3>Total Users</h3>
            <div style={metricValue}>{stats.users ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Total Organizations</h3>
            <div style={metricValue}>{stats.total ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Free Plans</h3>
            <div style={metricValue}>{stats.free ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Pro Plans</h3>
            <div style={metricValue}>{stats.pro ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Business Plans</h3>
            <div style={metricValue}>{stats.business ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Total Documents</h3>
            <div style={metricValue}>{stats.documents ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Total Stamp Actions</h3>
            <div style={metricValue}>{stats.audits ?? 0}</div>
          </div>

          <div style={cardStyle}>
            <h3>Failed Actions This Month</h3>
            <div style={metricValue}>{stats.failedActions ?? 0}</div>
          </div>
        </div>
      )}

      <section style={cardStyle}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 14,
            alignItems: "center",
            flexWrap: "wrap",
            marginBottom: 16,
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: 22 }}>Organizations</h3>
            <div style={{ color: "#64748b", marginTop: 4 }}>
              Monitor plans, billing, and usage limits.
            </div>
          </div>

          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search organizations..."
            style={{
              padding: "10px 12px",
              borderRadius: 12,
              border: "1px solid #cbd5e1",
              minWidth: 260,
            }}
          />
        </div>

        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thStyle}>Name</th>
                <th style={thStyle}>Plan</th>
                <th style={thStyle}>Billing</th>
                <th style={thStyle}>Documents</th>
                <th style={thStyle}>Stamps</th>
                <th style={thStyle}>Storage</th>
              </tr>
            </thead>

            <tbody>
              {filteredOrgs.map((o) => (
                <tr key={o.id}>
                  <td style={tdStyle}>
                    <strong>{o.name || "Unnamed"}</strong>
                    <div style={{ color: "#64748b", fontSize: 12 }}>
                      {o.slug || "—"}
                    </div>
                  </td>

                  <td style={tdStyle}>
                    <strong style={{ textTransform: "capitalize" }}>
                      {o.plan || "free"}
                    </strong>
                  </td>

                  <td style={tdStyle}>{badge(o.billing)}</td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.documents ?? 0)}
                  </td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.stamps ?? 0)}
                  </td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.storage ?? 0)}
                  </td>
                </tr>
              ))}

              {!filteredOrgs.length && (
                <tr>
                  <td style={tdStyle} colSpan={6}>
                    No organizations found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...cardStyle, marginTop: 24 }}>
        <h3 style={{ marginTop: 0, fontSize: 22 }}>Recent Failed Actions</h3>

        {!failedActions.length ? (
          <div style={{ color: "#64748b" }}>No failed actions found.</div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {failedActions.slice(0, 8).map((item) => (
              <div
                key={item._id}
                style={{
                  padding: 12,
                  border: "1px solid #fecaca",
                  background: "#fef2f2",
                  borderRadius: 12,
                  color: "#7f1d1d",
                }}
              >
                <strong>{item.action || "Unknown action"}</strong>
                <div style={{ fontSize: 13, marginTop: 4 }}>
                  Target: {item.target || item.document_id || "—"}
                </div>
                <div style={{ fontSize: 13, marginTop: 4 }}>
                  {item?.meta ? JSON.stringify(item.meta) : "No details"}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}