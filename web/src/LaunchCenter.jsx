import React, { useEffect, useState } from "react";
import api from "./api";

export default function LaunchCenter() {
  const [launch, setLaunch] = useState(null);
  const [system, setSystem] = useState(null);
  const [database, setDatabase] = useState(null);
  const [errors, setErrors] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = async () => {
    setLoading(true);
    setErr("");

    try {
      const [l, s, d, e] = await Promise.all([
        api.get("/health/launch"),
        api.get("/health/system"),
        api.get("/health/database"),
        api.get("/health/errors"),
      ]);

      setLaunch(l.data?.launch || null);
      setSystem(s.data?.system || null);
      setDatabase(d.data?.database || null);
      setErrors(e.data?.errors || e.data || null);
    } catch (error) {
      setErr(
        error?.response?.data?.error ||
          error?.message ||
          "Failed to load Launch Center."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const card = {
    border: "1px solid #dbe4f0",
    borderRadius: 14,
    padding: 16,
    background: "#fff",
    boxShadow: "0 4px 14px rgba(15,23,42,.05)",
  };

  const grid = {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 14,
    marginTop: 16,
  };

  const badge = (ok) => ({
    display: "inline-block",
    padding: "6px 10px",
    borderRadius: 999,
    fontWeight: 800,
    color: ok ? "#065f46" : "#991b1b",
    background: ok ? "#dcfce7" : "#fee2e2",
    border: ok ? "1px solid #86efac" : "1px solid #fecaca",
  });

  return (
    <section style={{ marginBottom: 24 }}>
      <div
        style={{
          ...card,
          borderColor: launch?.readyForBeta ? "#86efac" : "#fecaca",
          background: launch?.readyForBeta ? "#f0fdf4" : "#fff7ed",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <h2 style={{ margin: 0 }}>Launch Readiness Center</h2>
            <p style={{ margin: "6px 0 0", color: "#64748b" }}>
              Production health, activity, and beta-launch readiness.
            </p>
          </div>

          <button
            onClick={load}
            disabled={loading}
            style={{
              background: "#1d4ed8",
              color: "#fff",
              border: "none",
              borderRadius: 10,
              padding: "10px 16px",
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
              marginTop: 12,
              padding: 12,
              borderRadius: 10,
              background: "#fef2f2",
              color: "#991b1b",
              border: "1px solid #fecaca",
              fontWeight: 700,
            }}
          >
            {err}
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <span style={badge(!!launch?.readyForBeta)}>
            {launch?.readyForBeta ? "✅ Ready for Beta" : "⚠ Not Ready"}
          </span>
        </div>

        <div style={grid}>
          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Database</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {launch?.database || database?.state || "—"}
            </div>
          </div>

          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Failed Actions 24h</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {launch?.failedActions24h ?? 0}
            </div>
          </div>

          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Logins 24h</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {launch?.logins24h ?? 0}
            </div>
          </div>

          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Uploads 24h</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {launch?.uploads24h ?? 0}
            </div>
          </div>

          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Stamp Actions 24h</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {launch?.stampActions24h ?? 0}
            </div>
          </div>

          <div style={card}>
            <div style={{ color: "#64748b", fontWeight: 700 }}>Uptime</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>
              {system?.uptimeSeconds
                ? `${Math.floor(system.uptimeSeconds / 60)} min`
                : "—"}
            </div>
          </div>
        </div>

        <div style={{ marginTop: 18 }}>
          <h3 style={{ marginBottom: 8 }}>Critical Issues</h3>
          {launch?.criticalIssues?.length ? (
            <ul>
              {launch.criticalIssues.map((x, i) => (
                <li key={i} style={{ color: "#991b1b", fontWeight: 700 }}>
                  {x}
                </li>
              ))}
            </ul>
          ) : (
            <div style={{ color: "#065f46", fontWeight: 800 }}>
              ✅ No critical issues detected.
            </div>
          )}
        </div>

        <div style={{ marginTop: 18 }}>
          <h3 style={{ marginBottom: 8 }}>Recent Failed Actions</h3>
          {(launch?.failedActions24h || 0) > 0 ? (
  errors?.items?.length ? (
    <div style={{ display: "grid", gap: 8 }}>
      {errors.items.slice(0, 5).map((x) => (
        <div key={x._id} style={{
          padding: 10,
          borderRadius: 10,
          border: "1px solid #fecaca",
          background: "#fef2f2",
        }}>
          <b>{x.action || "Unknown action"}</b>
          <div style={{ fontSize: 13, color: "#64748b" }}>
            {x.meta?.email || "—"}
          </div>
        </div>
      ))}
    </div>
  ) : (
    <div style={{ color: "#991b1b", fontWeight: 800 }}>
      ⚠ Failed actions detected, but details could not be loaded.
    </div>
  )
) : (
  <div style={{ color: "#065f46", fontWeight: 800 }}>
    ✅ No failed actions in the last 24 hours.
  </div>
          )}
        </div>

        <div style={{ marginTop: 18, fontSize: 13, color: "#64748b" }}>
          Last checked: {launch?.timestamp ? new Date(launch.timestamp).toLocaleString() : "—"}
        </div>
      </div>
    </section>
  );
}