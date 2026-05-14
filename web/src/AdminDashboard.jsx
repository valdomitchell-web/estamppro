import React, { useEffect, useState } from "react";
import api from "./api";

export default function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [orgs, setOrgs] = useState([]);

  useEffect(() => {
    load();
  }, []);

  const load = async () => {
    const s = await api.get("/admin/overview");
    const o = await api.get("/admin/orgs");

    setStats(s.data.stats);
    setOrgs(o.data.orgs);
  };

  const cardStyle = {
  padding: 18,
  border: "1px solid #dbeafe",
  borderRadius: 14,
  background: "#fff",
  boxShadow: "0 2px 10px rgba(0,0,0,0.04)",
};

  return (
    <div style={{ padding: 20 }}>
      <h2>Admin Dashboard</h2>

      {stats && (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
      gap: 16,
      marginBottom: 24,
    }}
  >
    <div style={cardStyle}>
      <h3>Total Users</h3>
      <div>{stats.users}</div>
    </div>

    <div style={cardStyle}>
      <h3>Total Organizations</h3>
      <div>{stats.orgs}</div>
    </div>

    <div style={cardStyle}>
      <h3>Free Plans</h3>
      <div>{stats.free}</div>
    </div>

    <div style={cardStyle}>
      <h3>Pro Plans</h3>
      <div>{stats.pro}</div>
    </div>

    <div style={cardStyle}>
      <h3>Business Plans</h3>
      <div>{stats.business}</div>
    </div>

    <div style={cardStyle}>
      <h3>Total Documents</h3>
      <div>{stats.documents}</div>
    </div>

    <div style={cardStyle}>
      <h3>Total Stamp Actions</h3>
      <div>{stats.audits}</div>
    </div>
  </div>
)}
      {/* ORGS TABLE */}
      <table style={{ width: "100%", marginTop: 20 }}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Plan</th>
            <th>Billing</th>
            <th>Documents</th>
            <th>Stamps</th>
            <th>Storage</th>
          </tr>
        </thead>

        <tbody>
          {orgs.map((o) => (
            <tr key={o.id}>
              <td>{o.name}</td>
              <td>{o.plan}</td>
              <td>{o.billing}</td>

              <td>{o.percentages.documents}%</td>
              <td>{o.percentages.stamps}%</td>
              <td>{o.percentages.storage}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}