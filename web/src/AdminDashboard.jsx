import React, { useEffect, useMemo, useState } from "react";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  BarChart,
  Bar,
} from "recharts";
import api from "./api";

export default function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [failedActions, setFailedActions] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [search, setSearch] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [adminActions, setAdminActions] = useState([]);
  const [showAllAdminActions, setShowAllAdminActions] = useState(false);
  const [adminActionFilter, setAdminActionFilter] = useState("all");
  const [adminActionSearch, setAdminActionSearch] = useState("");
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [orgUsers, setOrgUsers] = useState([]);
  const [showUsers, setShowUsers] = useState(false);

  const load = async () => {
  setLoading(true);
  setErr("");

  const safeGet = async (url, fallback) => {
    try {
      const res = await api.get(url);
      return res.data || fallback;
    } catch (e) {
      console.error("Admin load failed:", url, e?.response?.data || e.message);
      setErr(e?.response?.data?.error || "admin_load_failed");
      return fallback;
    }
  };

  try {
    const [overview, orgsData, failed, charts, actions] = await Promise.all([
      safeGet("/admin/overview", { stats: null }),
      safeGet("/admin/orgs", { orgs: [] }),
      safeGet("/admin/failed-actions", { items: [] }),
      safeGet("/admin/charts", { timeline: [] }),
      safeGet("/admin/admin-actions", { items: [] }),
    ]);

    setStats(overview.stats || null);
    setOrgs(orgsData.orgs || []);
    setFailedActions(failed.items || []);
    setTimeline(charts.timeline || []);
    setAdminActions(actions.items || []);
  } finally {
    setLoading(false);
  }
};
  useEffect(() => {
    load();
  }, []);

  const suspendOrg = async (id) => {
  const adminPassword = window.prompt("Enter your admin password to suspend this organization:");

  if (!adminPassword) return;

  const reason = window.prompt("Reason for suspending this organization:");

if (!reason) {
  alert("A suspension reason is required.");
  return;
}

  if (!window.confirm("Suspend this organization? Users will be blocked from protected app actions.")) {
    return;
  }

  try {
    await api.post(`/admin/org/${id}/suspend`, { adminPassword, reason, });
    await load();
  } catch (e) {
    alert(e?.response?.data?.error || "Suspend failed");
  }
};

const reactivateOrg = async (id) => {
  const adminPassword = window.prompt("Enter your admin password to reactivate this organization:");

  if (!adminPassword) return;

  const reason = window.prompt("Reason for reactivating this organization:");

if (!reason) {
  alert("A reactivation reason is required.");
  return;
}

  if (!window.confirm("Reactivate this organization?")) {
    return;
  }

  try {
    await api.post(`/admin/org/${id}/reactivate`, { adminPassword,reason, });
    await load();
  } catch (e) {
    alert(e?.response?.data?.error || "Reactivate failed");
  }
};
//const sendResetLink = async (userId) => {
 // const adminPassword = window.prompt(
   // "Enter YOUR platform admin password to send a reset link:"
  //);

  //if (!adminPassword) return;

 // try {
   // const res = await api.post(`/admin/user/${userId}/send-reset-link`, {
  //adminPassword,
//});

//alert(
  //res?.data?.message ||
  //"Password reset email sent successfully."
//);
 // } catch (e) {
    //alert(
     // e?.response?.data?.error ||
     // e.message ||
    //  "Failed to send reset link."
   // );
 // }
//};

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

 const filteredAdminActions = useMemo(() => {
  let rows = adminActions;

  if (adminActionFilter === "suspend") {
    rows = rows.filter((a) => a.action === "admin.org.suspend");
  }

  if (adminActionFilter === "reactivate") {
    rows = rows.filter((a) => a.action === "admin.org.reactivate");
  }

  const q = adminActionSearch.trim().toLowerCase();

  if (q) {
    rows = rows.filter((a) =>
      [
        a.action,
        a.email,
        a.meta?.adminEmail,
        a.targetName,
        a.targetSlug,
        a.target,
        a.meta?.reason,
      ]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }

  return rows;
}, [adminActions, adminActionFilter, adminActionSearch]);

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

const dangerBtn = {
  padding: "6px 10px",
  borderRadius: 8,
  border: "none",
  background: "#dc2626",
  color: "#fff",
  cursor: "pointer",
  fontWeight: 700,
};

const successBtn = {
  padding: "6px 10px",
  borderRadius: 8,
  border: "none",
  background: "#16a34a",
  color: "#fff",
  cursor: "pointer",
  fontWeight: 700,
};

const primaryBtn = {
  padding: "8px 12px",
  borderRadius: 8,
  border: "none",
  background: "#2563eb",
  color: "#fff",
  cursor: "pointer",
  fontWeight: 600,
};

const secondaryBtn = {
  padding: "8px 12px",
  borderRadius: 8,
  border: "1px solid #bfdbfe",
  background: "#eff6ff",
  color: "#1d4ed8",
  cursor: "pointer",
  fontWeight: 700,
};

const actionConfig = {
  "admin.org.suspend": {
    icon: "🔴",
    color: "#dc2626",
  },
  "admin.org.reactivate": {
    icon: "🟢",
    color: "#16a34a",
  },
  "admin.user.password_reset": {
    icon: "🔵",
    color: "#2563eb",
  },
  "admin.user.password_changed": {
    icon: "🟣",
    color: "#7c3aed",
  },
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

const adminAlerts = useMemo(() => {
  const alerts = [];

  const highStorage = orgs.filter(
    (o) => Number(o.storage || 0) >= 90
  );

  if (highStorage.length) {
    alerts.push({
      type: "warning",
      text: `${highStorage.length} organizations above 90% storage`,
    });
  }

  const suspendedBusiness = orgs.filter(
    (o) =>
      o.plan?.toLowerCase() === "business" &&
      o.suspended
  );

  if (suspendedBusiness.length) {
    alerts.push({
      type: "danger",
      text: `${suspendedBusiness.length} suspended Business account(s)`,
    });
  }

  if ((failedActions?.length || 0) > 0) {
    alerts.push({
      type: "danger",
      text: `${failedActions.length} failed actions detected`,
    });
  }

  return alerts;
}, [orgs, failedActions]);

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

<div style={cardStyle}>
  <h3>Suspended Organizations</h3>
  <div style={metricValue}>{stats.suspended ?? 0}</div>
</div>

        </div>
      )}
<section
  style={{
    ...cardStyle,
    marginBottom: 24,
  }}
>
  <h2>Alerts Center</h2>

  {adminAlerts.length === 0 ? (
    <div
      style={{
        padding: 12,
        borderRadius: 10,
        background: "#ecfdf5",
        border: "1px solid #bbf7d0",
        color: "#166534",
        fontWeight: 800,
      }}
    >
      🟢 Healthy — No issues detected
    </div>
  ) : (
    adminAlerts.map((a, i) => {
      const isDanger = a.type === "danger";

      return (
        <div
          key={i}
          style={{
            padding: 12,
            marginBottom: 8,
            borderRadius: 10,
            background: isDanger ? "#fef2f2" : "#fffbeb",
            border: isDanger ? "1px solid #fecaca" : "1px solid #fde68a",
            color: isDanger ? "#991b1b" : "#92400e",
            fontWeight: 800,
          }}
        >
          {isDanger ? "🔴 Critical" : "🟡 Warning"} — {a.text}
        </div>
      );
    })
  )}
</section>

<section
  style={{
    ...cardStyle,
    marginBottom: 24,
  }}
>
  <h2>Quick Actions</h2>

  <div
    style={{
      display: "flex",
      gap: 12,
      flexWrap: "wrap",
      marginTop: 12,
    }}
  >
    <button style={primaryBtn}>
      📧 Broadcast Email
    </button>

    <button
      onClick={load}
      style={primaryBtn}
    >
      🔄 Refresh Analytics
    </button>

    <button style={primaryBtn}>
      📄 Export Report
    </button>

    <button style={primaryBtn}>
      ⚙ System Settings
    </button>
  </div>
</section>

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
                <th style={thStyle}>Actions</th>
              </tr>
            </thead>

            <tbody>
              {filteredOrgs.map((o) => (
                <tr
  key={o.id}
  onClick={() => setSelectedOrg(o)}
  style={{
    cursor: "pointer",
  }}
>
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

                  <td style={tdStyle}>
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
    {badge(o.billing)}

    {o.suspended && (
      <span
        style={{
          display: "inline-block",
          padding: "5px 10px",
          borderRadius: 999,
          background: "#fef2f2",
          color: "#991b1b",
          border: "1px solid #fecaca",
          fontWeight: 800,
          fontSize: 12,
        }}
      >
        Suspended
      </span>
    )}
  </div>
</td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.documents ?? 0)}
                  </td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.stamps ?? 0)}
                  </td>

                  <td style={tdStyle}>
                    {usageBar(o.percentages?.storage ?? 0)}
                  </td>

<td style={tdStyle}>
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
    {o.suspended ? (
  <button onClick={() => reactivateOrg(o.id)} style={successBtn}>
    Reactivate
  </button>
) : (
  <button onClick={() => suspendOrg(o.id)} style={dangerBtn}>
    Suspend
  </button>
)}
  </div>
</td>

                </tr>
              ))}

              {!filteredOrgs.length && (
                <tr>
                 <td style={tdStyle} colSpan={7}>
                    No organizations found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {selectedOrg && (
  <section
    style={{
      ...cardStyle,
      marginTop:24
    }}
  >
    <div
      style={{
        display:"flex",
        justifyContent:"space-between",
        alignItems:"center"
      }}
    >
      <h2>Organization Details — {selectedOrg.name}</h2>

      <button
        onClick={() => setSelectedOrg(null)}
        style={secondaryBtn}
      >
        Close
      </button>
    </div>

{showUsers && (
  <div
    style={{
      marginTop: 20,
      padding: 20,
      border: "1px solid #dbeafe",
      borderRadius: 14,
      background: "#fff",
    }}
  >
    <h3>Organization Users</h3>

    {orgUsers.length === 0 ? (
      <div>No users found</div>
    ) : (
      orgUsers.map((u) => (
        <div
          key={u._id}
          style={{
            display: "flex",
            justifyContent: "space-between",
            padding: 12,
            borderBottom: "1px solid #eee",
          }}
        >
          <div>
            <strong>{u.name || u.email}</strong>
            <div>{u.email}</div>
          </div>

          <button
            style={dangerBtn}
            onClick={() =>
              alert(`Remove ${u.email}`)
            }
          >
            Remove
          </button>
        </div>
      ))
    )}
  </div>
)}

    <div style={{marginTop:20}}>

      <p><b>Name:</b> {selectedOrg.name}</p>
      <p><b>Plan:</b> {selectedOrg.plan}</p>
      <p><b>Billing:</b> {selectedOrg.billing}</p>

      <p>
        <b>Documents:</b>
        {" "}
        {selectedOrg.percentages?.documents ?? 0}%
      </p>

      <p>
        <b>Stamps:</b>
        {" "}
       {selectedOrg.percentages?.stamps ?? 0}%
      </p>

      <p>
        <b>Storage:</b>
        {" "}
        {selectedOrg.percentages?.storage ?? 0}%
      </p>

     <div
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
      gap: 12,
      marginBottom: 20,
    }}
  >
    <div style={cardStyle}>
      <b>Users</b>
      <div>{selectedOrg.userCount || 0}</div>
    </div>

    <div style={cardStyle}>
      <b>Created</b>
      <div>
        {selectedOrg.created_at
          ? new Date(selectedOrg.created_at)
              .toLocaleDateString()
          : "-"}
      </div>
    </div>

    <div style={cardStyle}>
      <b>Last Activity</b>
      <div>
        {selectedOrg.lastActivity
          ? new Date(selectedOrg.lastActivity)
              .toLocaleString()
          : "-"}
      </div>
    </div>

    <div style={cardStyle}>
      <b>Owner Email</b>
      <div>{selectedOrg.ownerEmail || "-"}</div>
    </div>
  </div>

  {/* actions */}
  <div
    style={{
      display: "flex",
      gap: 10,
      flexWrap: "wrap",
    }}
  >
    {selectedOrg.suspended ? (
      <button
        onClick={() => reactivateOrg(selectedOrg.id)}
        style={successBtn}
      >
        Reactivate
      </button>
    ) : (
      <button
        onClick={() => suspendOrg(selectedOrg.id)}
        style={dangerBtn}
      >
        Suspend
      </button>
    )}

    <button
  style={primaryBtn}
  onClick={() => {
    const to = selectedOrg.ownerEmail || "";
    if (!to) {
      alert("No owner email found for this organization.");
      return;
    }

    window.location.href =
      `mailto:${to}?subject=${encodeURIComponent(
        "eStamp Pro Account Support"
      )}&body=${encodeURIComponent(
        `Hello ${selectedOrg.name || ""},\n\n`
      )}`;
  }}
>
  📧 Email Owner
</button>

    <button style={primaryBtn}>
      ⬆ Upgrade Plan
    </button>

    <button style={primaryBtn}>
      📄 View Audit Logs
    </button>

    <button
  style={primaryBtn}
  onClick={async () => {
    try {
      const res = await api.get(
        `/admin/org/${selectedOrg.id}/users`
      );

      setOrgUsers(res.data.users || []);
      setShowUsers(true);

    } catch (e) {
      alert("Could not load users");
    }
  }}
>
  👥 View Users
</button>
  </div>

</div>

  </section>
)}

<section style={{ ...cardStyle, marginTop: 24 }}>
  <h3 style={{ marginTop: 0, marginBottom: 18 }}>
    Platform Activity
  </h3>

  <div
    style={{
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 20,
    }}
  >
    <div>
      <h4>Documents vs Stamp Actions</h4>

      <div style={{ width: "100%", height: 320 }}>
        <ResponsiveContainer>
          <LineChart data={timeline}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="month" />
            <YAxis />
            <Tooltip />
            <Legend />

            <Line
              type="monotone"
              dataKey="documents"
              stroke="#2563eb"
              strokeWidth={3}
            />

            <Line
              type="monotone"
              dataKey="stamps"
              stroke="#16a34a"
              strokeWidth={3}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>

    <div>
      <h4>Failed Actions Trend</h4>

      <div style={{ width: "100%", height: 320 }}>
        <ResponsiveContainer>
          <BarChart data={timeline}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="month" />
            <YAxis />
            <Tooltip />

            <Bar
              dataKey="failed"
              fill="#dc2626"
              radius={[6, 6, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  </div>
</section>

<section style={{ ...cardStyle, marginTop: 24 }}>
  <h3 style={{ marginTop: 0, fontSize: 22 }}>Recent Admin Actions</h3>

<div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
  {[
    ["all", "All"],
    ["suspend", "Suspensions"],
    ["reactivate", "Reactivations"],
  ].map(([key, label]) => (
    <button
      key={key}
      onClick={() => setAdminActionFilter(key)}
      style={{
        padding: "7px 10px",
        borderRadius: 999,
        border:
          adminActionFilter === key
            ? "1px solid #1d4ed8"
            : "1px solid #bfdbfe",
        background: adminActionFilter === key ? "#1d4ed8" : "#eff6ff",
        color: adminActionFilter === key ? "#fff" : "#1d4ed8",
        fontWeight: 800,
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  ))}
</div>

<input
  value={adminActionSearch}
  onChange={(e) => setAdminActionSearch(e.target.value)}
  placeholder="Search admin actions..."
  style={{
    padding: "9px 12px",
    borderRadius: 12,
    border: "1px solid #bfdbfe",
    minWidth: 260,
    marginBottom: 12,
  }}
/>
  {!adminActions.length ? (
    <div style={{ color: "#64748b" }}>No admin actions found.</div>
  ) : (
    <div style={{ display: "grid", gap: 10 }}>
      {filteredAdminActions
  .slice(0, showAllAdminActions ? 20 : 5)
  .map((item) => (
        <div
          key={item._id}
          style={{
            padding: 12,
            border: "1px solid #bfdbfe",
            background: "#eff6ff",
            borderRadius: 12,
            color: "#1e3a8a",
          }}
        >
          {(() => {
  const labels = {
    "admin.org.suspend": "Organization Suspended",
    "admin.org.reactivate": "Organization Reactivated",
    "admin.user.password_reset": "Password Reset Sent",
    "admin.user.password_changed": "Password Changed",
  };

  const cfg = actionConfig[item.action] || {
    icon: "⚪",
    color: "#374151",
  };

  return (
    <div
      style={{
        fontSize: 22,
        fontWeight: 700,
        color: cfg.color,
        marginBottom: 8,
      }}
    >
      {cfg.icon} {labels[item.action] || item.action}
    </div>
  );
})()}

          <div style={{ fontSize: 13, marginTop: 4 }}>
  By: {item.email || item.meta?.adminEmail || "Unknown admin (older log)"}
</div>

<div style={{ fontSize: 13, marginTop: 4 }}>
  Target: {item.targetName || item.targetSlug || item.target || "—"}
</div>

{item.meta?.reason && (
  <div style={{ fontSize: 13, marginTop: 4 }}>
    Reason: {item.meta.reason}
  </div>
)}
          <div style={{ fontSize: 13, marginTop: 4 }}>
            {item.created_at
              ? new Date(item.created_at).toLocaleString()
              : "No date"}
          </div>
        </div>
      ))}
    </div>
  )}

{filteredAdminActions.length > 5 && (
  <button
    onClick={() => setShowAllAdminActions((v) => !v)}
    style={{
      marginTop: 12,
      padding: "8px 12px",
      borderRadius: 10,
      border: "1px solid #bfdbfe",
      background: "#eff6ff",
      color: "#1d4ed8",
      fontWeight: 800,
      cursor: "pointer",
    }}
  >
    {showAllAdminActions ? "Show Less" : "Show More"}
  </button>
)}
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