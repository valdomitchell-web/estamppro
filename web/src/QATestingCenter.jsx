import React, { useMemo, useState } from "react";

const TESTS = [
  ["Authentication", "Register new user"],
  ["Authentication", "Login / logout"],
  ["Authentication", "Password reset"],
  ["Organization", "Create organization"],
  ["Organization", "Plan display and limits"],
  ["Stamping", "Upload PDF"],
  ["Stamping", "Create stamp"],
  ["Stamping", "Apply stamp"],
  ["Stamping", "Bulk stamp ZIP"],
  ["Signatures", "Draw signature"],
  ["Signatures", "Save and reuse signature"],
  ["Verification", "Verify stamped PDF"],
  ["Verification", "QR verification"],
  ["Team", "Invite teammate"],
  ["Team", "Accept invite"],
  ["Team", "Role permissions"],
  ["Audit", "Audit table"],
  ["Audit", "CSV export"],
  ["Audit", "PDF export"],
  ["Billing", "Upgrade flow"],
  ["Email", "Branded email send"],
  ["Admin", "Suspend/reactivate org"],
  ["Admin", "Launch Center"],
  ["Mobile", "Mobile layout check"],
];

export default function QATestingCenter() {
  const [results, setResults] = useState({});

  const setResult = (key, value) => {
    setResults((prev) => ({ ...prev, [key]: value }));
  };

  const stats = useMemo(() => {
    const values = TESTS.map((_, i) => results[i] || "pending");
    const passed = values.filter((x) => x === "pass").length;
    const failed = values.filter((x) => x === "fail").length;
    const blocked = values.filter((x) => x === "blocked").length;
    const pending = values.filter((x) => x === "pending").length;
    const total = TESTS.length;
    const progress = Math.round(((passed + failed + blocked) / total) * 100);
    const releaseScore = Math.round((passed / total) * 100);

    return { total, passed, failed, blocked, pending, progress, releaseScore };
  }, [results]);

  const card = {
    border: "1px solid #dbeafe",
    borderRadius: 14,
    padding: 14,
    background: "#fff",
  };

  const statusColor = {
    pass: "#16a34a",
    fail: "#dc2626",
    blocked: "#d97706",
    pending: "#64748b",
  };

  return (
    <section
      style={{
        border: "1px solid #bfdbfe",
        borderRadius: 16,
        padding: 18,
        background: "#fff",
        marginBottom: 20,
      }}
    >
      <h2 style={{ marginTop: 0 }}>QA Testing Center</h2>
      <p style={{ color: "#64748b", marginTop: -8 }}>
        Pre-launch testing checklist for core platform workflows.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(120px,1fr))",
          gap: 12,
          marginBottom: 18,
        }}
      >
        <div style={card}><b>Total</b><h2>{stats.total}</h2></div>
        <div style={card}><b>Passed</b><h2>{stats.passed}</h2></div>
        <div style={card}><b>Failed</b><h2>{stats.failed}</h2></div>
        <div style={card}><b>Blocked</b><h2>{stats.blocked}</h2></div>
        <div style={card}><b>Progress</b><h2>{stats.progress}%</h2></div>
        <div style={card}><b>Release Score</b><h2>{stats.releaseScore}%</h2></div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", minWidth: 760, borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>Module</th>
              <th style={th}>Test</th>
              <th style={th}>Status</th>
              <th style={th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {TESTS.map(([module, test], i) => {
              const value = results[i] || "pending";

              return (
                <tr key={i}>
                  <td style={td}>{module}</td>
                  <td style={td}>{test}</td>
                  <td style={{ ...td, fontWeight: 800, color: statusColor[value] }}>
                    {value.toUpperCase()}
                  </td>
                  <td style={td}>
                    {["pass", "fail", "blocked", "pending"].map((x) => (
                      <button
                        key={x}
                        onClick={() => setResult(i, x)}
                        style={{
                          marginRight: 6,
                          padding: "6px 9px",
                          borderRadius: 8,
                          border: "1px solid #bfdbfe",
                          background: value === x ? "#1d4ed8" : "#eff6ff",
                          color: value === x ? "#fff" : "#1d4ed8",
                          fontWeight: 800,
                          cursor: "pointer",
                        }}
                      >
                        {x}
                      </button>
                    ))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

const th = {
  textAlign: "left",
  padding: 10,
  borderBottom: "1px solid #e2e8f0",
};

const td = {
  padding: 10,
  borderBottom: "1px solid #f1f5f9",
};