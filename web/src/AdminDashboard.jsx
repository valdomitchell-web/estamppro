import React, { useEffect, useMemo, useState } from "react";
import LaunchCenter from "./LaunchCenter";

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
import QATestingCenter from "./QATestingCenter";

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
  const [noOrgUsers, setNoOrgUsers] = useState([]);
  const [noOrgTotal, setNoOrgTotal] = useState(0);
  const [noOrgRegistrations24h, setNoOrgRegistrations24h] = useState(0);
  const [showBroadcast, setShowBroadcast] = useState(false);
  const [broadcastTarget, setBroadcastTarget] = useState("all");
  const [broadcastSubject, setBroadcastSubject] = useState("");
  const [broadcastMessage, setBroadcastMessage] = useState("");
  const [broadcastPreview, setBroadcastPreview] = useState(null);
  const [broadcastBusy, setBroadcastBusy] = useState(false);
  const [broadcastStatus, setBroadcastStatus] = useState("");
  const [broadcastTestEmail, setBroadcastTestEmail] = useState("");

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
    const [overview, orgsData, failed, charts, actions, noOrg] =
      await Promise.all([
        safeGet("/admin/overview", { stats: null }),
        safeGet("/admin/orgs", { orgs: [] }),
        safeGet("/admin/failed-actions", { items: [] }),
        safeGet("/admin/charts", { timeline: [] }),
        safeGet("/admin/admin-actions", { items: [] }),
        safeGet("/admin/users/no-org", {
          total: 0,
          newRegistrations24h: 0,
          users: [],
        }),
      ]);

    setStats(overview.stats || null);
    setOrgs(orgsData.orgs || []);
    setFailedActions(failed.items || []);
    setTimeline(charts.timeline || []);
    setAdminActions(actions.items || []);
    setNoOrgUsers(noOrg.users || []);
    setNoOrgTotal(noOrg.total || 0);
    setNoOrgRegistrations24h(noOrg.newRegistrations24h || 0);
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

  const previewBroadcast = async () => {
  setBroadcastBusy(true);
  setBroadcastStatus("");
  setBroadcastPreview(null);

  try {
    const res = await api.post("/admin/broadcast/preview", {
      target: broadcastTarget,
    });

    setBroadcastPreview(res.data || null);
    setBroadcastStatus(
      `Preview ready: ${res.data?.count ?? 0} recipient(s).`
    );
  } catch (e) {
    setBroadcastStatus(
      e?.response?.data?.error ||
        e?.message ||
        "Broadcast preview failed."
    );
  } finally {
    setBroadcastBusy(false);
  }
};

const sendBroadcastTest = async () => {
  if (!broadcastSubject.trim() || !broadcastMessage.trim()) {
    alert("Enter a subject and message first.");
    return;
  }

  if (!broadcastTestEmail.trim()) {
    alert("Enter a test email address.");
    return;
  }

  const adminPassword = window.prompt(
    "Enter your admin password to send this test email:"
  );

  if (!adminPassword) return;

  setBroadcastBusy(true);
  setBroadcastStatus("");

  try {
    const res = await api.post("/admin/broadcast/test", {
      to: broadcastTestEmail,
      subject: broadcastSubject,
      message: broadcastMessage,
      adminPassword,
    });

    setBroadcastStatus(
      `Test email sent to ${res.data?.recipient || broadcastTestEmail}.`
    );
  } catch (e) {
    setBroadcastStatus(
      e?.response?.data?.error ||
        e?.message ||
        "Test email failed."
    );
  } finally {
    setBroadcastBusy(false);
  }
};

const sendBroadcast = async () => {
  if (!broadcastPreview) {
    alert("Preview recipients before sending.");
    return;
  }

  if (!broadcastSubject.trim() || !broadcastMessage.trim()) {
    alert("Enter a subject and message first.");
    return;
  }

  const count = Number(broadcastPreview?.count || 0);

  if (!count) {
    alert("No recipients matched this broadcast.");
    return;
  }

  const confirmed = window.confirm(
    `Send this broadcast to ${count} recipient(s)?`
  );

  if (!confirmed) return;

  const adminPassword = window.prompt(
    "Enter your admin password to send this broadcast:"
  );

  if (!adminPassword) return;

  setBroadcastBusy(true);
  setBroadcastStatus("");

  try {
    const res = await api.post("/admin/broadcast/send", {
      target: broadcastTarget,
      subject: broadcastSubject,
      message: broadcastMessage,
      adminPassword,
    });

    setBroadcastStatus(
      `Broadcast complete. Sent: ${res.data?.sent ?? 0}. Failed: ${
        res.data?.failed ?? 0
      }.`
    );
  } catch (e) {
    setBroadcastStatus(
      e?.response?.data?.error ||
        e?.message ||
        "Broadcast failed."
    );
  } finally {
    setBroadcastBusy(false);
  }
};

const changeUserRole = async (user, role) => {
  if (!selectedOrg?.id) return;

  const adminPassword = window.prompt("Enter your admin password to change this user's role:");
  if (!adminPassword) return;

  const reason = window.prompt("Reason for changing this user's role:");
  if (!reason) {
    alert("A role change reason is required.");
    return;
  }

  try {
    await api.post(`/admin/org/${selectedOrg.id}/users/${user._id}/role`, {
      adminPassword,
      role,
      reason,
    });

    const res = await api.get(`/admin/org/${selectedOrg.id}/users`);
    setOrgUsers(res.data.users || []);
    await load();

    alert("User role updated successfully.");
  } catch (e) {
    alert(e?.response?.data?.error || "Role update failed");
  }
};
  const removeOrgUser = async (user) => {
  if (!selectedOrg?.id) return;

  const adminPassword = window.prompt("Enter your admin password to remove this user:");
  if (!adminPassword) return;

  const reason = window.prompt("Reason for removing this user:");
  if (!reason) {
    alert("A removal reason is required.");
    return;
  }

  if (!window.confirm(`Remove ${user.email} from ${selectedOrg.name}?`)) {
    return;
  }

  try {
    await api.post(`/admin/org/${selectedOrg.id}/users/${user._id}/remove`, {
      adminPassword,
      reason,
    });

    const res = await api.get(`/admin/org/${selectedOrg.id}/users`);
    setOrgUsers(res.data.users || []);
    await load();

    alert("User removed successfully.");
  } catch (e) {
    alert(e?.response?.data?.error || "Remove user failed");
  }
};

const openOrgDetails = async (org) => {
  setSelectedOrg(org);
  setOrgUsers([]);
  setShowUsers(true);

  try {
    const res = await api.get(`/admin/org/${org.id}/users`);
    setOrgUsers(res.data.users || []);
  } catch (e) {
    setOrgUsers([]);
  }
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

  const isManagedBillingOrg = (o) => {
  const provider = String(
    o.billingProvider ||
      o.provider ||
      ""
  ).toLowerCase();

  return ["fastspring", "stripe"].includes(provider);
};

  const overdueOrgs = orgs.filter((o) => {
    if (!isManagedBillingOrg(o)) return false;
  const billing = String(o.billingStatus || o.billing || "").toLowerCase();
  const subscription = String(o.subscriptionStatus || "").toLowerCase();

  return (
    billing === "overdue" ||
    billing === "past_due" ||
    subscription === "overdue" ||
    subscription === "past_due"
  );
});

if (overdueOrgs.length) {
  alerts.push({
    type: "danger",
    text: `${overdueOrgs.length} organization(s) with overdue payments`,
    details: overdueOrgs.slice(0, 5).map((o) => ({
      _id: `billing-overdue-${o.id}`,
      action: `${o.name || "Unnamed organization"} — Payment overdue`,
      meta: {
        message: `Plan: ${o.plan || "free"} · Provider: ${
          o.billingProvider || "unknown"
        }`,
      },
    })),
  });
}

const failedOrderOrgs = orgs.filter(
  (o) =>
    isManagedBillingOrg(o) &&
    String(o.billingStatus || o.billing || "").toLowerCase() === "order_failed"
);

if (failedOrderOrgs.length) {
  alerts.push({
    type: "danger",
    text: `${failedOrderOrgs.length} organization(s) with failed billing orders`,
    details: failedOrderOrgs.slice(0, 5).map((o) => ({
      _id: `billing-order-failed-${o.id}`,
      action: `${o.name || "Unnamed organization"} — Order issue`,
      meta: {
        message: `Plan: ${o.plan || "free"} · Provider: ${
          o.billingProvider || "unknown"
        }`,
      },
    })),
  });
}

const refundedOrgs = orgs.filter(
  (o) =>
   isManagedBillingOrg(o) &&
    String(o.billingStatus || o.billing || "").toLowerCase() === "refunded"
);

if (refundedOrgs.length) {
  alerts.push({
    type: "warning",
    text: `${refundedOrgs.length} organization(s) with refunds requiring review`,
    details: refundedOrgs.slice(0, 5).map((o) => ({
      _id: `billing-refunded-${o.id}`,
      action: `${o.name || "Unnamed organization"} — Refund under review`,
      meta: {
        message: `Plan: ${o.plan || "free"} · Provider: ${
          o.billingProvider || "unknown"
        }`,
      },
    })),
  });
}

const canceledOrgs = orgs.filter( 
  (o) =>
   isManagedBillingOrg(o) &&
    String(o.billingStatus || o.billing || "").toLowerCase() === "canceled"
);

if (canceledOrgs.length) {
  alerts.push({
    type: "warning",
    text: `${canceledOrgs.length} organization(s) with canceled subscriptions`,
    details: canceledOrgs.slice(0, 5).map((o) => ({
      _id: `billing-canceled-${o.id}`,
      action: `${o.name || "Unnamed organization"} — Subscription canceled`,
      meta: {
        message: `Plan: ${o.plan || "free"} · Provider: ${
          o.billingProvider || "unknown"
        }`,
      },
    })),
  });
}

 const highStorage = orgs.filter(
  (o) => Number(o.percentages?.storage || 0) >= 90
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
    details: failedActions.slice(0, 5),
  });
}

  return alerts;
}, [orgs, failedActions]);

  return (
    <div style={{ padding: 20 }}>
     <LaunchCenter />
<QATestingCenter />

      <div
      style={{
  padding: 16,
  borderRadius: 14,
  border: "1px solid #86efac",
  background: "#f0fdf4",
  marginBottom: 20
}}
    >
</div>
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
            gridTemplateColumns:
"repeat(auto-fit,minmax(120px,1fr))",
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
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "flex-start",
      gap: 16,
      flexWrap: "wrap",
      marginBottom: 18,
    }}
  >
    <div>
      <h2 style={{ margin: 0 }}>Users Without Organization</h2>
      <div style={{ color: "#64748b", marginTop: 6 }}>
        Free and other user accounts that have not created or joined an organization.
      </div>
    </div>
  </div>

  <div
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
      gap: 14,
      marginBottom: 20,
    }}
  >
    <div style={cardStyle}>
      <div style={{ color: "#64748b", fontWeight: 700 }}>
        Users Without Organization
      </div>
      <div style={metricValue}>{noOrgTotal}</div>
    </div>

    <div style={cardStyle}>
      <div style={{ color: "#64748b", fontWeight: 700 }}>
        New No-Org Registrations (24h)
      </div>
      <div style={metricValue}>{noOrgRegistrations24h}</div>
    </div>
  </div>

  <div style={{ overflowX: "auto" }}>
    <table
      style={{
        width: "100%",
        minWidth: 980,
        borderCollapse: "collapse",
      }}
    >
      <thead>
        <tr>
          <th style={thStyle}>Email</th>
          <th style={thStyle}>Plan</th>
          <th style={thStyle}>Created</th>
          <th style={thStyle}>Documents</th>
          <th style={thStyle}>Documents 24h</th>
          <th style={thStyle}>Stamp Actions</th>
          <th style={thStyle}>Stamp Actions 24h</th>
        </tr>
      </thead>

      <tbody>
        {noOrgUsers.map((u) => (
          <tr key={u.id}>
            <td style={tdStyle}>
              <strong>{u.email || "—"}</strong>
            </td>

            <td style={tdStyle}>
              <span style={{ textTransform: "capitalize", fontWeight: 700 }}>
                {u.plan || "free"}
              </span>
            </td>

            <td style={tdStyle}>
              {u.created_at
                ? new Date(u.created_at).toLocaleString("en-US", {
                    timeZone: "America/Grenada",
                  })
                : "—"}
            </td>

            <td style={tdStyle}>{u.documents ?? 0}</td>

            <td style={tdStyle}>{u.documents24h ?? 0}</td>

            <td style={tdStyle}>{u.stampActions ?? 0}</td>

            <td style={tdStyle}>{u.stampActions24h ?? 0}</td>
          </tr>
        ))}

        {!noOrgUsers.length && (
          <tr>
            <td style={tdStyle} colSpan={7}>
              No users without an organization found.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  </div>
</section>

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
          <div>
  {isDanger ? "🔴 Critical" : "🟡 Warning"} — {a.text}
</div>

{a.details?.length ? (
  <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
    {a.details.map((x) => (
      <div
        key={x._id}
        style={{
          padding: 10,
          borderRadius: 10,
          background: "#fff",
          border: "1px solid #fecaca",
          color: "#334155",
          fontWeight: 500,
        }}
      >
        <div style={{ fontWeight: 800, color: "#991b1b" }}>
          {x.action || "Unknown action"}
        </div>

        <div style={{ fontSize: 13, marginTop: 3 }}>
          {x.meta?.message || "No error message available"}
        </div>

        {x.meta?.url && (
          <div style={{ fontSize: 12, color: "#64748b", marginTop: 3 }}>
            {x.meta.url}
          </div>
        )}
      </div>
    ))}
  </div>
) : null}       </div>
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
    <button
      onClick={() => setShowBroadcast((v) => !v)}
      style={primaryBtn}
    >
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

{showBroadcast && (
  <section
    style={{
      ...cardStyle,
      marginBottom: 24,
    }}
  >
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        gap: 12,
        alignItems: "center",
        flexWrap: "wrap",
        marginBottom: 18,
      }}
    >
      <div>
        <h2 style={{ margin: 0 }}>Broadcast Email</h2>
        <div style={{ color: "#64748b", marginTop: 5 }}>
          Preview recipients, send a test, then send the broadcast.
        </div>
      </div>

      <button
        onClick={() => setShowBroadcast(false)}
        style={secondaryBtn}
      >
        Close
      </button>
    </div>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))",
        gap: 14,
      }}
    >
      <div>
        <label style={{ fontWeight: 800 }}>Target</label>
        <select
          value={broadcastTarget}
          onChange={(e) => {
            setBroadcastTarget(e.target.value);
            setBroadcastPreview(null);
            setBroadcastStatus("");
          }}
          style={{
            width: "100%",
            marginTop: 6,
            padding: "10px 12px",
            borderRadius: 10,
            border: "1px solid #cbd5e1",
          }}
        >
          <option value="all">All Users</option>
          <option value="free">Free</option>
          <option value="pro">Pro</option>
          <option value="business">Business</option>
          <option value="no_org">Users Without Organization</option>
        </select>
      </div>

      <div>
        <label style={{ fontWeight: 800 }}>Test Email</label>
        <input
          type="email"
          value={broadcastTestEmail}
          onChange={(e) => setBroadcastTestEmail(e.target.value)}
          placeholder="your@email.com"
          style={{
            width: "100%",
            marginTop: 6,
            padding: "10px 12px",
            borderRadius: 10,
            border: "1px solid #cbd5e1",
            boxSizing: "border-box",
          }}
        />
      </div>
    </div>

    <div style={{ marginTop: 14 }}>
      <label style={{ fontWeight: 800 }}>Subject</label>
      <input
        value={broadcastSubject}
        onChange={(e) => setBroadcastSubject(e.target.value)}
        maxLength={160}
        placeholder="Email subject"
        style={{
          width: "100%",
          marginTop: 6,
          padding: "10px 12px",
          borderRadius: 10,
          border: "1px solid #cbd5e1",
          boxSizing: "border-box",
        }}
      />
    </div>

    <div style={{ marginTop: 14 }}>
      <label style={{ fontWeight: 800 }}>Message</label>
      <textarea
        value={broadcastMessage}
        onChange={(e) => setBroadcastMessage(e.target.value)}
        maxLength={10000}
        rows={8}
        placeholder="Write the broadcast message..."
        style={{
          width: "100%",
          marginTop: 6,
          padding: "12px",
          borderRadius: 10,
          border: "1px solid #cbd5e1",
          resize: "vertical",
          boxSizing: "border-box",
          fontFamily: "inherit",
        }}
      />
    </div>

    <div
      style={{
        display: "flex",
        gap: 10,
        flexWrap: "wrap",
        marginTop: 16,
      }}
    >
      <button
        onClick={previewBroadcast}
        disabled={broadcastBusy}
        style={secondaryBtn}
      >
        Preview Recipients
      </button>

      <button
        onClick={sendBroadcastTest}
        disabled={broadcastBusy}
        style={secondaryBtn}
      >
        Send Test
      </button>

      <button
        onClick={sendBroadcast}
        disabled={
          broadcastBusy ||
          !broadcastPreview ||
          !broadcastPreview?.count
        }
        style={{
          ...primaryBtn,
          opacity:
            broadcastBusy ||
            !broadcastPreview ||
            !broadcastPreview?.count
              ? 0.5
              : 1,
          cursor:
            broadcastBusy ||
            !broadcastPreview ||
            !broadcastPreview?.count
              ? "not-allowed"
              : "pointer",
        }}
      >
        Send Broadcast
      </button>
    </div>

    {broadcastStatus && (
      <div
        style={{
          marginTop: 14,
          padding: 12,
          borderRadius: 10,
          background: "#f8fafc",
          border: "1px solid #cbd5e1",
          fontWeight: 700,
        }}
      >
        {broadcastStatus}
      </div>
    )}

    {broadcastPreview && (
      <div
        style={{
          marginTop: 16,
          padding: 14,
          borderRadius: 12,
          background: "#eff6ff",
          border: "1px solid #bfdbfe",
        }}
      >
        <div style={{ fontWeight: 900, marginBottom: 8 }}>
          {broadcastPreview.count ?? 0} recipient(s)
        </div>

        {(broadcastPreview.recipients || []).length > 0 && (
          <div style={{ display: "grid", gap: 5 }}>
            {(broadcastPreview.recipients || []).map((r) => (
              <div
                key={r.id}
                style={{ fontSize: 13, color: "#334155" }}
              >
                {r.email} — {r.plan}
              </div>
            ))}
          </div>
        )}

        {(broadcastPreview.count || 0) > 10 && (
          <div
            style={{
              marginTop: 8,
              fontSize: 12,
              color: "#64748b",
            }}
          >
            Showing the first 10 recipients.
          </div>
        )}
      </div>
    )}
  </section>
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
          <table style={{
  width:"100%",
  minWidth:"900px",
  borderCollapse:"collapse"
}}>
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
  onClick={() => openOrgDetails(o)}
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
  <strong>
    {u.name ||
 `${u.firstName || ""} ${u.lastName || ""}`.trim() ||
 u.email?.split("@")[0] ||
 "Unnamed User"}
  </strong>

  <div
    style={{
      fontSize: 13,
      color: "#6b7280",
      marginTop: 2
    }}
  >
    {u.email}
  </div>

  <div
    style={{
      fontSize: 12,
      color: "#9ca3af"
    }}
  >
    {u.role || "user"}
  </div>
</div>

<select
  value={u.role || "user"}
  onChange={(e) => changeUserRole(u, e.target.value)}
  style={{
    padding: "8px 10px",
    borderRadius: 8,
    border: "1px solid #cbd5e1",
    fontWeight: 700,
    marginRight: 10,
  }}
>
  <option value="owner">Owner</option>
  <option value="admin">Admin</option>
  <option value="verifier">Verifier</option>
  <option value="user">Member</option>
</select>

          <button
  style={dangerBtn}
  onClick={() => removeOrgUser(u)}
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
  <strong>Users</strong>
  <div>{orgUsers.length || selectedOrg.userCount || 0}</div>
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
  onClick={() => setShowUsers((v) => !v)}
>
  {showUsers ? "👥 Hide Users" : "👥 Show Users"}
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
display:"grid",
gridTemplateColumns:
"repeat(auto-fit,minmax(420px,1fr))",
gap:20
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
            {failedActions.slice(0, 5).map((item) => (
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