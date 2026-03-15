import React, { useEffect, useRef, useState } from "react";
import { api } from "./api";
import StampDesigner from "./StampDesigner.jsx";

export default function App() {
  const [email, setEmail] = useState("valdomitchell@gmail.com");
  const [password, setPassword] = useState("");
  const [me, setMe] = useState(null);
  const [audit, setAudit] = useState([]);
  const [file, setFile] = useState(null);
  const [err, setErr] = useState("");

  const [lastDocId, setLastDocId] = useState(null);
  const [stamps, setStamps] = useState([]);
  const [selectedStamp, setSelectedStamp] = useState("");
  const [stampPassword, setStampPassword] = useState("");
  const [applyResult, setApplyResult] = useState(null);

  const [stampPage, setStampPage] = useState(0);
  const [stampX, setStampX] = useState(50);
  const [stampY, setStampY] = useState(50);
  const [stampScale, setStampScale] = useState(1.0);
  const [stampOpacity, setStampOpacity] = useState(1);

  const [verifyFile, setVerifyFile] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);

  const [dragX, setDragX] = useState(200);
  const [dragY, setDragY] = useState(200);

  const pageRef = useRef(null);
  const boxRef = useRef(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`${api.defaults.baseURL}/health`, {
          credentials: "omit",
          cache: "no-store",
        });
        if (!r.ok) throw new Error(`API health ${r.status}`);
      } catch (e) {
        console.error(e);
        setErr("API not reachable. Check API URL and CORS.");
      }
    })();

    (async () => {
      try {
        const r = await api.get("/auth/me").catch(() => null);
        if (r?.data?.user) {
          setMe(r.data.user);
        }
      } catch {}
    })();
  }, []);

  const showErr = (e) => {
    console.error(e);
    const data = e?.response?.data;
    const msg =
      data?.detail ||
      data?.error ||
      e?.message ||
      "Unknown error";
    setErr(msg);
  };

  const register = async () => {
    setErr("");
    try {
      const r = await api.post("/auth/register", { email, password });
      if (r.data?.token) {
        localStorage.setItem("access_token", r.data.token);
      }
      setMe(r.data?.user || null);
    } catch (e) {
      showErr(e);
    }
  };

  const login = async () => {
    setErr("");
    try {
      const r = await api.post("/auth/login", { email, password });
      if (r.data?.token) {
        localStorage.setItem("access_token", r.data.token);
      }
      setMe(r.data?.user || null);
    } catch (e) {
      showErr(e);
    }
  };

  const logout = async () => {
    setErr("");
    try {
      await api.post("/auth/logout");
    } catch {}
    localStorage.removeItem("access_token");
    setMe(null);
  };

  const loadAudit = async () => {
    setErr("");
    try {
      const r = await api.get("/audit/my", { params: { limit: 50 } });
      setAudit(r.data?.items || []);
    } catch (e) {
      showErr(e);
    }
  };

  const loadStamps = async () => {
    setErr("");
    try {
      const r = await api.get("/stamps");
      setStamps(r.data?.stamps || []);
    } catch (e) {
      showErr(e);
    }
  };

  const uploadPdf = async () => {
    if (!file) {
      alert("Choose a PDF first.");
      return;
    }

    setErr("");
    try {
      const fd = new FormData();
      fd.append("file", file);

      const r = await api.post("/documents/upload/documents", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const docId = r.data?.document?.id || null;
      setLastDocId(docId);
      alert("Uploaded document id: " + (docId || "unknown"));
      await loadAudit();
    } catch (e) {
      showErr(e);
    }
  };

  const applyStamp = async () => {
    if (!selectedStamp) {
      alert("Choose a stamp first.");
      return;
    }
    if (!lastDocId) {
      alert("Upload a PDF document first.");
      return;
    }
    if (!stampPassword) {
      alert("Enter the stamp password.");
      return;
    }

    setErr("");
    setApplyResult(null);

    try {
      const body = {
        documentId: lastDocId,
        page: Number(stampPage) || 0,
        x: Number(stampX) || 0,
        y: Number(stampY) || 0,
        scale: Number(stampScale) || 1,
        opacity: Number(stampOpacity) || 1,
        password: stampPassword,
      };

      const r = await api.post(`/stamps/${selectedStamp}/apply`, body);
      setApplyResult(r.data || null);

      if (r.data?.downloadUrl) {
        window.open(r.data.downloadUrl, "_blank");
      } else if (r.data?.downloadPath) {
        window.open(`${api.defaults.baseURL}${r.data.downloadPath}`, "_blank");
      }

      await loadAudit();
    } catch (e) {
      showErr(e);
    }
  };

  const verifyPdf = async () => {
    if (!verifyFile) {
      alert("Please choose a PDF first");
      return;
    }

    setErr("");
    setVerifyResult(null);

    try {
      const fd = new FormData();
      fd.append("file", verifyFile);

      const r = await api.post("/verify", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      setVerifyResult(r.data || null);
    } catch (e) {
      showErr(e);
    }
  };

  const handlePreviewMouseDown = (e) => {
    if (!pageRef.current || !boxRef.current) return;
    if (!boxRef.current.contains(e.target)) return;

    e.preventDefault();

    const pageRect = pageRef.current.getBoundingClientRect();
    const boxRect = boxRef.current.getBoundingClientRect();
    const offsetX = e.clientX - boxRect.left;
    const offsetY = e.clientY - boxRect.top;

    const onMove = (ev) => {
      let x = ev.clientX - pageRect.left - offsetX;
      let y = ev.clientY - pageRect.top - offsetY;

      const maxX = pageRect.width - boxRect.width;
      const maxY = pageRect.height - boxRect.height;

      if (x < 0) x = 0;
      if (y < 0) y = 0;
      if (x > maxX) x = maxX;
      if (y > maxY) y = maxY;

      setDragX(x);
      setDragY(y);

      const pageHeight = pageRect.height;
      const pdfX = Math.round(x);
      const pdfY = Math.round(pageHeight - y - boxRect.height);

      setStampX(pdfX);
      setStampY(pdfY);
    };

    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const cardStyle = {
    background: "#ffffff",
    border: "1px solid #e5e7eb",
    borderRadius: 14,
    padding: 20,
    boxShadow: "0 2px 8px rgba(0,0,0,0.04)",
  };

  const sectionTitle = {
    marginTop: 0,
    marginBottom: 16,
    fontSize: 28,
  };

  const inputStyle = {
    padding: "10px 12px",
    borderRadius: 8,
    border: "1px solid #d1d5db",
    minWidth: 220,
    fontSize: 15,
  };

  const labelStyle = {
    display: "block",
    marginBottom: 6,
    fontWeight: 600,
    color: "#374151",
  };

  const buttonStyle = {
    background: "#2563eb",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: 600,
  };

  const buttonSecondary = {
    background: "#f3f4f6",
    color: "#111827",
    border: "1px solid #d1d5db",
    borderRadius: 8,
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: 600,
  };

  const resultBox = {
    background: "#f9fafb",
    padding: 12,
    fontSize: 12,
    borderRadius: 8,
    marginTop: 14,
    overflowX: "auto",
  };

  const thStyle = {
    textAlign: "left",
    padding: 12,
    borderBottom: "1px solid #e5e7eb",
  };

  const tdStyle = {
    padding: 12,
    verticalAlign: "top",
  };

  const verifyCardStyle = {
    marginTop: 20,
    padding: 20,
    borderRadius: 12,
    border: "1px solid #dbe4f0",
    background: "#ffffff",
    boxShadow: "0 6px 18px rgba(0,0,0,0.05)",
    maxWidth: 700,
  };

  const verifyDetails = verifyResult?.details || {};
  const embedded = verifyResult?.embedded || {};
  const embeddedPayload = embedded?.payload || {};
  const verified = !!verifyResult?.verified;

  return (
    <div
      style={{
        fontFamily: "Arial, sans-serif",
        background: "#f6f8fb",
        minHeight: "100vh",
        padding: "24px",
        color: "#1f2937",
      }}
    >
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 24,
          }}
        >
          <div>
            <h1 style={{ margin: 0, fontSize: 42 }}>eStamp Pro</h1>
            <div style={{ color: "#6b7280", marginTop: 4 }}>
              Secure digital stamping and verification
            </div>
          </div>
          <div
            style={{
              background: "#fff",
              border: "1px solid #e5e7eb",
              borderRadius: 10,
              padding: "10px 14px",
              boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
            }}
          >
            <strong>User:</strong> {me?.email || "Not logged in"}
          </div>
        </div>

        {err && (
          <div
            style={{
              background: "#fef2f2",
              border: "1px solid #fecaca",
              color: "#991b1b",
              padding: 14,
              borderRadius: 10,
              marginBottom: 20,
              fontWeight: 500,
            }}
          >
            {String(err)}
          </div>
        )}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 20,
            marginBottom: 20,
          }}
        >
          <section style={cardStyle}>
            <h2 style={sectionTitle}>Auth</h2>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
              <input
                style={inputStyle}
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <input
                style={inputStyle}
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button style={buttonStyle} onClick={register}>Register</button>
              <button style={buttonStyle} onClick={login}>Login</button>
              <button style={buttonSecondary} onClick={logout}>Logout</button>
            </div>

            <div style={{ marginTop: 14, color: "#374151" }}>
              <strong>Logged in as:</strong> {me?.email || "—"}
            </div>
          </section>

          <section style={cardStyle}>
            <h2 style={sectionTitle}>Upload PDF</h2>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="file"
                accept="application/pdf"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              <button style={buttonStyle} onClick={uploadPdf}>Upload</button>
            </div>

            <div style={{ marginTop: 14, color: "#374151" }}>
              <strong>Last uploaded document id:</strong> {lastDocId || "—"}
            </div>
          </section>
        </div>

        <section style={{ ...cardStyle, marginBottom: 20 }}>
          <h2 style={sectionTitle}>Stamp Designer</h2>
          <StampDesigner
            onSaved={(stamp) => {
              loadStamps();
              if (stamp?.id) setSelectedStamp(stamp.id);
            }}
          />
        </section>

        <section style={{ ...cardStyle, marginBottom: 20 }}>
          <h2 style={sectionTitle}>Apply Stamp</h2>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <label style={labelStyle}>Choose stamp</label>
              <select
                style={inputStyle}
                value={selectedStamp}
                onChange={(e) => setSelectedStamp(e.target.value)}
              >
                <option value="">Select stamp…</option>
                {stamps.map((s) => (
                  <option key={s._id || s.id} value={s._id || s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={labelStyle}>Stamp password</label>
              <input
                style={inputStyle}
                type="password"
                placeholder="Stamp password"
                value={stampPassword}
                onChange={(e) => setStampPassword(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>Page</label>
              <input
                style={inputStyle}
                type="number"
                min={0}
                value={stampPage}
                onChange={(e) => setStampPage(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>Scale</label>
              <input
                style={inputStyle}
                type="number"
                step="0.1"
                value={stampScale}
                onChange={(e) => setStampScale(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>X</label>
              <input
                style={inputStyle}
                type="number"
                value={stampX}
                onChange={(e) => setStampX(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>Y</label>
              <input
                style={inputStyle}
                type="number"
                value={stampY}
                onChange={(e) => setStampY(e.target.value)}
              />
            </div>

            <div>
              <label style={labelStyle}>Opacity</label>
              <input
                style={inputStyle}
                type="number"
                min={0}
                max={1}
                step="0.1"
                value={stampOpacity}
                onChange={(e) => setStampOpacity(e.target.value)}
              />
            </div>
          </div>

          <div style={{ marginTop: 12, marginBottom: 12 }}>
            <div style={{ fontWeight: "bold", marginBottom: 4 }}>
              Placement Preview
            </div>
            <div
              ref={pageRef}
              onMouseDown={handlePreviewMouseDown}
              style={{
                position: "relative",
                width: 612,
                height: 792,
                border: "1px solid #ccc",
                background: "white",
                overflow: "hidden",
              }}
            >
              <div
                ref={boxRef}
                className="stamp-preview-box"
                style={{
                  position: "absolute",
                  left: dragX,
                  top: dragY,
                  width: 160,
                  height: 80,
                  border: "2px dashed red",
                  borderRadius: 4,
                  background: "rgba(255,0,0,0.03)",
                  cursor: "move",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                }}
              >
                Stamp
              </div>
            </div>
            <small style={{ display: "block", marginTop: 4 }}>
              Drag the red box to choose where the stamp will appear. X/Y fields above update automatically.
            </small>
          </div>

          <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button style={buttonSecondary} onClick={loadStamps}>Reload My Stamps</button>
            <button style={buttonStyle} onClick={applyStamp}>Apply Stamp</button>
          </div>

          {applyResult && (
            <pre style={resultBox}>
              {JSON.stringify(applyResult, null, 2)}
            </pre>
          )}
        </section>

        <section style={{ ...cardStyle, marginBottom: 20 }}>
          <h2 style={sectionTitle}>Verify Stamped PDF</h2>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input
              type="file"
              accept="application/pdf"
              onChange={(e) => setVerifyFile(e.target.files?.[0] || null)}
            />
            <button style={buttonStyle} onClick={verifyPdf}>Verify PDF</button>
          </div>

          {verifyResult && (
            <div style={verifyCardStyle}>
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 18,
                  marginBottom: 12,
                  color: verified ? "#166534" : "#991b1b",
                }}
              >
                {verified ? "Verified Document" : "Verification Failed"}
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "180px 1fr",
                  gap: "10px 12px",
                }}
              >
                <div style={{ fontWeight: 600 }}>Stamp ID</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>
                  {String(verifyDetails?.stamp_id || embeddedPayload?.stamp_id || "—")}
                </div>

                <div style={{ fontWeight: 600 }}>Document ID</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>
                  {String(verifyDetails?.document_id || embeddedPayload?.doc_id || "—")}
                </div>

                <div style={{ fontWeight: 600 }}>Verification Code</div>
                <div style={{ fontFamily: "Consolas, monospace" }}>
                  {embeddedPayload?.verify_code || "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Timestamp</div>
                <div>
                  {verifyDetails?.timestamp
                    ? new Date(verifyDetails.timestamp).toLocaleString()
                    : embeddedPayload?.ts
                    ? new Date(embeddedPayload.ts).toLocaleString()
                    : "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Page</div>
                <div>{embeddedPayload?.page ?? verifyDetails?.page ?? "—"}</div>

                <div style={{ fontWeight: 600 }}>Position</div>
                <div>
                  X: {embeddedPayload?.x ?? verifyDetails?.x ?? "—"} | Y:{" "}
                  {embeddedPayload?.y ?? verifyDetails?.y ?? "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Scale / Opacity</div>
                <div>
                  {embeddedPayload?.scale ?? verifyDetails?.scale ?? "—"} /{" "}
                  {embeddedPayload?.opacity ?? verifyDetails?.opacity ?? "—"}
                </div>

                <div style={{ fontWeight: 600 }}>Source</div>
                <div>{verifyResult?.source || "audit/pdf"}</div>
              </div>
            </div>
          )}
        </section>

        <section style={cardStyle}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 12,
            }}
          >
            <h2 style={{ ...sectionTitle, marginBottom: 0 }}>Audit Log</h2>
            <button style={buttonSecondary} onClick={loadAudit}>
              Load My Audit
            </button>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff" }}>
              <thead>
                <tr style={{ background: "#f9fafb" }}>
                  <th style={thStyle}>Time</th>
                  <th style={thStyle}>Action</th>
                  <th style={thStyle}>OK</th>
                  <th style={thStyle}>Target</th>
                  <th style={thStyle}>Meta</th>
                </tr>
              </thead>
              <tbody>
                {audit.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: 12, color: "#6b7280" }}>
                      No audit rows yet.
                    </td>
                  </tr>
                ) : (
                  audit.map((it) => (
                    <tr key={it._id} style={{ borderTop: "1px solid #e5e7eb" }}>
                      <td style={tdStyle}>
                        {it.time ? new Date(it.time).toLocaleString() : "—"}
                      </td>
                      <td style={tdStyle}>{it.action ?? "—"}</td>
                      <td style={tdStyle}>
                        {typeof it.ok === "boolean" ? String(it.ok) : (it.ok ?? "—")}
                      </td>
                      <td style={tdStyle}>
                        {it.target?._id || it.document_id || it.target || "—"}
                      </td>
                      <td style={tdStyle}>
                        {it.meta ? JSON.stringify(it.meta) : "{}"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}