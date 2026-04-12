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

  return (
    <div style={{ padding: 20 }}>
      <h2>Admin Dashboard</h2>

      {/* STATS */}
      {stats && (
        <div style={{ display: "flex", gap: 20 }}>
          <div>Total Orgs: {stats.total}</div>
          <div>Free: {stats.free}</div>
          <div>Pro: {stats.pro}</div>
          <div>Business: {stats.business}</div>
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