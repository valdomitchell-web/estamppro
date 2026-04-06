import React, { useEffect, useMemo, useState } from "react";
import api from "./api";

const cardStyle = {
  background: "#fff",
  border: "1px solid #dbe4f0",
  borderRadius: 16,
  padding: 20,
  boxShadow: "0 2px 10px rgba(0,0,0,0.03)",
};

function parseRecipients(value) {
  return String(value || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

export default function AnalyticsReportsSettings({ currentPlan = "free" }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [sending, setSending] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const [enabled, setEnabled] = useState(false);
  const [frequency, setFrequency] = useState("weekly");
  const [day, setDay] = useState("monday");
  const [recipients, setRecipients] = useState("");
  const [lastSentAt, setLastSentAt] = useState("");

  const normalizedPlan = String(currentPlan || "free").toLowerCase();
  const canUseWeeklyReports = normalizedPlan === "business";

  const recipientList = useMemo(() => parseRecipients(recipients), [recipients]);
  const hasRecipients = recipientList.length > 0;

  async function loadSettings({ keepMessage = false } = {}) {
  setLoading(true);
  setErr("");
  if (!keepMessage) setMsg("");
  try {
      const r = await api.get("/orgs/reports/settings");
      const data = r?.data || {};
      setEnabled(!!data.analytics_reports_enabled);
      setFrequency(data.analytics_report_frequency || "weekly");
      setDay(data.analytics_report_day || "monday");
      setRecipients(
        Array.isArray(data.analytics_recipients)
          ? data.analytics_recipients.join(", ")
          : ""
      );
      setLastSentAt(data.last_analytics_report_sent_at || "");
    } catch (e) {
      setErr(
        e?.response?.data?.error ||
          e?.message ||
          "Failed to load analytics report settings."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSettings();
  }, []);

  async function saveSettings() {
    setSaving(true);
    setErr("");
    setMsg("");

    try {
      if (!canUseWeeklyReports) {
        setErr("Weekly reports are available on the Business plan.");
        return;
      }

      const autoEnabled = hasRecipients;

      const payload = {
        analytics_reports_enabled: autoEnabled,
        analytics_report_frequency: frequency,
        analytics_report_day: day,
        analytics_recipients: recipientList,
      };

      await api.post("/orgs/reports/settings", payload);

      setEnabled(autoEnabled);
      setMsg(
        autoEnabled
          ? "Analytics reports saved and enabled."
          : "Analytics reports saved and disabled because no recipients were entered."
      );

      await loadSettings({ keepMessage: true });
    } catch (e) {
      setErr(
        e?.response?.data?.error ||
          e?.message ||
          "Failed to save analytics report settings."
      );
    } finally {
      setSaving(false);
    }
  }

  async function sendNow() {
    setSending(true);
    setErr("");
    setMsg("");

    try {
      if (!canUseWeeklyReports) {
        setErr("Weekly reports are available on the Business plan.");
        return;
      }

      if (!hasRecipients) {
        setErr("Add at least one report recipient before sending.");
        return;
      }

      if (!enabled) {
        await api.post("/orgs/reports/settings", {
          analytics_recipients: recipientList,
          analytics_reports_enabled: true,
          analytics_report_frequency: frequency,
          analytics_report_day: day,
        });
        setEnabled(true);
      }

      await api.post("/orgs/reports/send-now");
      setMsg("Weekly analytics report sent.");
      await loadSettings({ keepMessage: true });
    } catch (e) {
      setErr(
        e?.response?.data?.error ||
          e?.message ||
          "Failed to send analytics report."
      );
    } finally {
      setSending(false);
    }
  }

  const statusText = !canUseWeeklyReports
    ? "Business plan required"
    : hasRecipients
    ? "Will auto-enable on save"
    : "Will auto-disable on save";

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
  <h2 style={{ margin: 0, fontSize: 22 }}>
    Weekly analytics reports
  </h2>

  <div style={{ color: "#64748b", marginTop: 6 }}>
    Send branded analytics PDFs to organization admins automatically.
  </div>

  <div style={{ color: "#64748b", marginTop: 6 }}>
    Current plan:{" "}
    <strong style={{ textTransform: "capitalize" }}>
      {normalizedPlan}
    </strong>
  </div>

  {!canUseWeeklyReports && (
    <div
      style={{
        marginTop: 14,
        padding: "14px 16px",
        borderRadius: 14,
        background: "linear-gradient(135deg, #eff6ff, #f8fafc)",
        border: "1px solid #bfdbfe",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 12,
      }}
    >
      <div>
        <div style={{ fontWeight: 700, color: "#1e3a8a" }}>
          Upgrade to Business to unlock weekly reports
        </div>
        <div style={{ fontSize: 13, color: "#475569", marginTop: 4 }}>
          Automated PDF reports, delivery tracking, and analytics history.
        </div>
      </div>

      <button
        onClick={() => {
          // 👉 OPTION A: route to billing page
          window.location.href = "/billing";

          // 👉 OPTION B (if you use Stripe checkout link)
          // window.location.href = "https://your-stripe-link";
        }}
        style={{
          padding: "10px 16px",
          borderRadius: 12,
          border: "none",
          background: "#1d4ed8",
          color: "#fff",
          fontWeight: 700,
          cursor: "pointer",
          boxShadow: "0 4px 14px rgba(29,78,216,0.25)",
        }}
      >
        Upgrade to Business
      </button>
    </div>
  )}

          </div>
        </div>

        {loading ? (
          <div style={{ color: "#64748b", marginBottom: 14 }}>Loading…</div>
        ) : null}

        {msg ? (
          <div
            style={{
              marginBottom: 14,
              color: "#166534",
              background: "#f0fdf4",
              border: "1px solid #bbf7d0",
              borderRadius: 12,
              padding: "10px 12px",
            }}
          >
            {msg}
          </div>
        ) : null}

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

        <div
          style={{
            marginBottom: 16,
            color: hasRecipients ? "#166534" : "#92400e",
            background: hasRecipients ? "#f0fdf4" : "#fff7ed",
            border: `1px solid ${hasRecipients ? "#bbf7d0" : "#fed7aa"}`,
            borderRadius: 12,
            padding: "10px 12px",
          }}
        >
          {statusText}
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 16,
          }}
        >
          <div
            style={{
              border: "1px solid #e2e8f0",
              borderRadius: 14,
              padding: 16,
              background: "#f8fafc",
            }}
          >
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                fontWeight: 700,
                color: "#0f172a",
              }}
            >
              <input
                type="checkbox"
                checked={enabled || hasRecipients}
                readOnly
              />
              Enable weekly analytics reports
            </label>

            <div style={{ marginTop: 8, fontSize: 12, color: "#64748b" }}>
              This now turns on automatically when at least one recipient is entered.
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 13, color: "#64748b", marginBottom: 6 }}>
                Frequency
              </div>
              <select
                value={frequency}
                onChange={(e) => {
                  setFrequency(e.target.value);
                  setErr("");
                  setMsg("");
             
                }}
                disabled={!canUseWeeklyReports}
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 12,
                  border: "1px solid #cbd5e1",
                  background: "#fff",
                }}
              >
                <option value="weekly">Weekly</option>
              </select>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 13, color: "#64748b", marginBottom: 6 }}>
                Send day
              </div>
              <select
                value={day}
                onChange={(e) => setDay(e.target.value)}
                disabled={!canUseWeeklyReports}
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 12,
                  border: "1px solid #cbd5e1",
                  background: "#fff",
                }}
              >
                <option value="monday">Monday</option>
                <option value="tuesday">Tuesday</option>
                <option value="wednesday">Wednesday</option>
                <option value="thursday">Thursday</option>
                <option value="friday">Friday</option>
                <option value="saturday">Saturday</option>
                <option value="sunday">Sunday</option>
              </select>
            </div>
          </div>

          <div
            style={{
              border: "1px solid #e2e8f0",
              borderRadius: 14,
              padding: 16,
              background: "#f8fafc",
            }}
          >
            <div style={{ fontSize: 13, color: "#64748b", marginBottom: 6 }}>
              Report recipients
            </div>
            <textarea
              value={recipients}
              onChange={(e) => {
                setRecipients(e.target.value);
                setErr("");
                setMsg("");
              }}
              rows={6}
              placeholder="admin@yourorg.com, manager@yourorg.com"
              disabled={!canUseWeeklyReports}
              style={{
                width: "100%",
                padding: "12px",
                borderRadius: 12,
                border: "1px solid #cbd5e1",
                background: "#fff",
                resize: "vertical",
                fontFamily: "inherit",
                boxSizing: "border-box",
              }}
            />
            <div style={{ fontSize: 12, color: "#64748b", marginTop: 8 }}>
              Separate multiple email addresses with commas.
            </div>

            <div style={{ marginTop: 16, fontSize: 13, color: "#334155" }}>
              <strong>Recipient count:</strong> {recipientList.length}
            </div>

            <div style={{ marginTop: 8, fontSize: 13, color: "#334155" }}>
              <strong>Last report sent:</strong>{" "}
              {lastSentAt ? new Date(lastSentAt).toLocaleString() : "—"}
            </div>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            marginTop: 18,
          }}
        >
          <button
            onClick={saveSettings}
            disabled={saving || !canUseWeeklyReports}
            style={{
              padding: "10px 16px",
              borderRadius: 12,
              border: "1px solid #93c5fd",
              background: "#eff6ff",
              color: "#1d4ed8",
              fontWeight: 700,
              cursor: saving || !canUseWeeklyReports ? "not-allowed" : "pointer",
              opacity: !canUseWeeklyReports ? 0.65 : 1,
            }}
          >
            {saving ? "Saving..." : "Save report settings"}
          </button>

          <button
            onClick={sendNow}
            disabled={sending || !canUseWeeklyReports || !hasRecipients}
            style={{
              padding: "10px 16px",
              borderRadius: 12,
              border: "1px solid #cbd5e1",
              background: "#fff",
              color: "#0f172a",
              fontWeight: 700,
              cursor:
                sending || !canUseWeeklyReports || !hasRecipients
                  ? "not-allowed"
                  : "pointer",
              opacity: !canUseWeeklyReports || !hasRecipients ? 0.65 : 1,
            }}
          >
            {sending ? "Sending..." : "Send weekly report now"}
          </button>
        </div>
      </div>
    </section>
  );
}