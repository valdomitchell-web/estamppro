// web/src/App.jsx
import React, { useEffect, useState } from "react";
import { api } from "./api";

export default function App() {
  const [email, setEmail] = useState("valdomitchell@gmail.com");
  const [password, setPassword] = useState("");
  const [me, setMe] = useState(null);
  const [audit, setAudit] = useState([]);
  const [file, setFile] = useState(null);
  const [err, setErr] = useState("");

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

  const uploadPdf = async () => {
    if (!file) return alert("Choose a PDF first.");
    setErr("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const r = await api.post("/documents/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      alert("Uploaded: " + (r.data?.id || r.data?.ok || "ok"));
      await loadAudit();
    } catch (e) { showErr(e); }
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
