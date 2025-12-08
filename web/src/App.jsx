// web/src/App.jsx
import React, { useState, useEffect, useRef } from "react";
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

const [stampPage, setStampPage] = useState(0);       // 0 = first page
const [stampX, setStampX] = useState(50);            // left offset
const [stampY, setStampY] = useState(50);            // bottom offset
const [stampScale, setStampScale] = useState(1.0);   // relative size
const [stampOpacity, setStampOpacity] = useState(1); // 0–1

const [dragX, setDragX] = useState(200);
const [dragY, setDragY] = useState(200);
const pageRef = useRef(null);
const boxRef = useRef(null);
  // quick up-check so page always renders
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
        setErr("API not reachable. Check API_BASE and CORS.");
      }
    })();

    // restore user from token (optional “/auth/me”)
    (async () => {
      try {
        const r = await api.get("/auth/me").catch(() => null);
        if (r?.data?.user) setMe(r.data.user);
      } catch {}
    })();
  }, []);

  const showErr = (e) =>
    setErr(e?.response?.data?.error || e?.message || String(e));

  const register = async () => {
    setErr("");
    try {
      const r = await api.post("/auth/register", { email, password });
      if (r.data?.token) localStorage.setItem("access_token", r.data.token);
      setMe(r.data?.user || null);
    } catch (e) { showErr(e); }
  };

  const login = async () => {
    setErr("");
    try {
      const r = await api.post("/auth/login", { email, password });
      if (r.data?.token) localStorage.setItem("access_token", r.data.token);
      setMe(r.data?.user || null);
    } catch (e) { showErr(e); }
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
    } catch (e) { showErr(e); }
  };

  const loadStamps = async () => {
  setErr("");
  try {
    const r = await api.get("/stamps");
    setStamps(r.data?.stamps || []);
  } catch (e) { showErr(e); }
};

const applyStamp = async () => {
  if (!selectedStamp) return alert("Choose a stamp first.");
  if (!lastDocId) return alert("Upload a PDF document first.");
  if (!stampPassword) return alert("Enter the stamp password.");
  setErr("");
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

 const uploadPdf = async () => {
  if (!file) return alert("Choose a PDF first.");
  setErr("");
  try {
    const fd = new FormData();
    fd.append("file", file);

    const r = await api.post("/documents/upload/documents", fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    console.log("Upload response:", r.data);

    // Be flexible about where the id is:
    const doc =
      r.data?.document ||
      r.data?.doc ||
      r.data ||
      null;

    const docId = r.data?.document?.id;
setLastDocId(docId || null);             

    alert("Uploaded document id: " + (docId || "unknown"));

    await loadAudit();
  } catch (e) {
    showErr(e);
  }
};

const handlePreviewMouseDown = (e) => {
  if (!pageRef.current || !boxRef.current) return;

  // Only start drag if the red box itself is clicked
  if (!boxRef.current.contains(e.target)) return;

  e.preventDefault();

  const pageRect = pageRef.current.getBoundingClientRect();
  const boxRect = boxRef.current.getBoundingClientRect();
  const offsetX = e.clientX - boxRect.left;
  const offsetY = e.clientY - boxRect.top;

  const onMove = (ev) => {
    let x = ev.clientX - pageRect.left - offsetX;
    let y = ev.clientY - pageRect.top - offsetY;

    // clamp within page area
    const maxX = pageRect.width - boxRect.width;
    const maxY = pageRect.height - boxRect.height;

    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x > maxX) x = maxX;
    if (y > maxY) y = maxY;

    setDragX(x);
    setDragY(y);

    // Convert browser coords (top-left origin) to PDF coords (bottom-left origin)
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

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>
      <h1>eStamp Pro — Dashboard</h1>

      {err && (
        <div style={{ background:"#fee", color:"#900", border:"1px solid #f99", padding:12, marginBottom:16 }}>
          {String(err)}
        </div>
      )}

      {/* AUTH */}
      <section style={{ border:"1px solid #ddd", padding:16, marginBottom:24 }}>
        <h2>Auth</h2>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          <input style={{ minWidth:320 }} placeholder="email" value={email} onChange={(e)=>setEmail(e.target.value)} />
          <input style={{ minWidth:240 }} type="password" placeholder="password" value={password} onChange={(e)=>setPassword(e.target.value)} />
          <button onClick={register}>Register</button>
          <button onClick={login}>Login</button>
          <button onClick={logout}>Logout</button>
        </div>
        <div style={{ marginTop:8 }}>
          <strong>Logged in as:</strong> {me?.email || "—"}
        </div>
      </section>

      {/* UPLOAD */}
      <section style={{ border:"1px solid #ddd", padding:16, marginBottom:24 }}>
        <h2>Upload PDF</h2>
        <input type="file" accept="application/pdf" onChange={(e)=>setFile(e.target.files?.[0]||null)} />
        <button onClick={uploadPdf} style={{ marginLeft:8 }}>Upload</button>
      </section>

            {/* STAMP DESIGNER */}
      <section style={{ border:"1px solid #ddd", padding:16, marginBottom:24 }}>
        <h2>Stamp Designer</h2>
        <p style={{ marginBottom:8 }}>Create a PNG stamp and save it to your account.</p>
        <StampDesigner />
        <button style={{ marginTop:8 }} onClick={loadStamps}>Reload My Stamps</button>
      </section>

      {/* APPLY STAMP */}
            <section style={{ border:"1px solid #ddd", padding:16, marginBottom:24 }}>
        <h2>Apply Stamp to Last Uploaded PDF</h2>
        <div style={{ marginBottom:8 }}>
          <div>Last uploaded document id: <strong>{lastDocId || "—"}</strong></div>
        </div>

        {/* stamp selection + password */}
        <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginBottom:8 }}>
          <select
            value={selectedStamp}
            onChange={(e)=>setSelectedStamp(e.target.value)}
          >
            <option value="">Select stamp…</option>
            {stamps.map(s => (
              <option key={s._id || s.id} value={s._id || s.id}>{s.name}</option>
            ))}
          </select>
          <input
            type="password"
            placeholder="Stamp password"
            value={stampPassword}
            onChange={(e)=>setStampPassword(e.target.value)}
          />
          <button onClick={loadStamps}>Load My Stamps</button>
        </div>

        {/* placement controls */}
        <div style={{ display:"flex", gap:12, flexWrap:"wrap", marginBottom:8 }}>
          <label>
            Page
            <input
              type="number"
              min={0}
              style={{ width:70, marginLeft:4 }}
              value={stampPage}
              onChange={(e)=>setStampPage(e.target.value)}
            />
          </label>
          <label>
            X
            <input
              type="number"
              style={{ width:80, marginLeft:4 }}
              value={stampX}
              onChange={(e)=>setStampX(e.target.value)}
            />
          </label>
          <label>
            Y
            <input
              type="number"
              style={{ width:80, marginLeft:4 }}
              value={stampY}
              onChange={(e)=>setStampY(e.target.value)}
            />
          </label>
          <label>
            Scale
            <input
              type="number"
              step="0.1"
              style={{ width:80, marginLeft:4 }}
              value={stampScale}
              onChange={(e)=>setStampScale(e.target.value)}
            />
          </label>
          <label>
            Opacity
            <input
              type="number"
              min={0}
              max={1}
              step="0.1"
              style={{ width:80, marginLeft:4 }}
              value={stampOpacity}
              onChange={(e)=>setStampOpacity(e.target.value)}
            />
          </label>
      {/* Placement preview */}
      <div style={{ marginTop: 12 }}>
        <div style={{ fontWeight: "bold", marginBottom: 4 }}>
          Placement Preview
        </div>
        <div
          ref={pageRef}
          onMouseDown={handlePreviewMouseDown}
          style={{
            position: "relative",
            width: 612,          // approx US Letter width in PDF units
            height: 792,         // approx height
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
          Drag the red box to choose where the stamp will appear. X/Y fields
          above update automatically.
        </small>
      </div>

          <button onClick={applyStamp}>Apply Stamp</button>
        </div>

        {applyResult && (
          <pre style={{ background:"#f9fafb", padding:8, fontSize:12 }}>
{JSON.stringify(applyResult, null, 2)}
          </pre>
        )}
      </section>

      {/* AUDIT */}
      <section style={{ border:"1px solid #ddd", padding:16 }}>
        <h2>Audit Log</h2>
        <button onClick={loadAudit}>Load My Audit (latest 50)</button>
        <table style={{ width:"100%", marginTop:12, borderCollapse:"collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign:"left", borderBottom:"1px solid #ccc" }}>Time</th>
              <th style={{ textAlign:"left", borderBottom:"1px solid #ccc" }}>Action</th>
              <th style={{ textAlign:"left", borderBottom:"1px solid #ccc" }}>OK</th>
              <th style={{ textAlign:"left", borderBottom:"1px solid #ccc" }}>Target</th>
              <th style={{ textAlign:"left", borderBottom:"1px solid #ccc" }}>Meta</th>
            </tr>
          </thead>
          <tbody>
            {audit.length === 0 ? (
              <tr><td colSpan={5} style={{ padding:8, color:"#666" }}>No audit rows yet.</td></tr>
            ) : audit.map((it) => (
              <tr key={it._id}>
                <td style={{ padding:6 }}>
                  {it.time ? new Date(it.time).toLocaleString() : "—"}
                </td>
                <td style={{ padding:6 }}>{it.action ?? "—"}</td>
                <td style={{ padding:6 }}>
                  {typeof it.ok === "boolean" ? String(it.ok) : (it.ok ?? "—")}
                </td>
                <td style={{ padding:6 }}>
                  {it.target?._id || it.document_id || it.target || "—"}
                </td>
                <td style={{ padding:6 }}>{it.meta ? JSON.stringify(it.meta) : "{}"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
