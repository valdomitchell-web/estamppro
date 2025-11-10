import React, { useEffect, useState } from 'react';
import { api } from './api';

// helpers
const j = r => r.json();

export default function App() {
  // auth
  const [email, setEmail] = useState(localStorage.getItem('last_email') || '');
  const [password, setPassword] = useState('');
  const [me, setMe] = useState(null);

  // upload + stamp
  const [uploading, setUploading] = useState(false);
  const [uploadedDoc, setUploadedDoc] = useState(null); // {_id, name, size, s3Key?}
  const [page, setPage] = useState(1);
  const [x, setX] = useState(50);
  const [y, setY] = useState(50);
  const [scale, setScale] = useState(0.5);
  const [opacity, setOpacity] = useState(1.0);
  const [stampText, setStampText] = useState('');
  const [stamping, setStamping] = useState(false);
  const [result, setResult] = useState(null); // { downloadUrl, s3SignedUrl, id }

  // verify (v2 – password-free)
  const [verifying, setVerifying] = useState(false);
  const [verifyOk, setVerifyOk] = useState(null);

  // audit
  const [audit, setAudit] = useState([]);

  // detect session
  useEffect(() => {
    (async () => {
      try {
        const res = await api.get('/auth/me', { credentials: 'include' });
        if (res.ok) {
          const data = await j(res);
          setMe(data.user || { email: data.email });
        } else {
          setMe(null);
        }
      } catch {
        setMe(null);
      }
    })();
  }, []);

  const onRegister = async () => {
    try {
      const r = await api.post('/auth/register', {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      });
      if (!r.ok) throw new Error(await r.text());
      alert('Registered. Now click Login.');
    } catch (e) {
      alert('Register failed: ' + e.message);
    }
  };

  const onLogin = async () => {
    try {
      const r = await api.post('/auth/login', {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      });
      if (!r.ok) throw new Error(await r.text());
      localStorage.setItem('last_email', email);
      setMe({ email });
      alert('Logged in');
    } catch (e) {
      alert('Login failed: ' + e.message);
    }
  };

  const onLogout = async () => {
    try {
      await api.post('/auth/logout', { credentials: 'include' });
    } finally {
      setMe(null);
    }
  };

  const onUpload = async (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setResult(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await api.post('/documents/upload', {
        body: fd,
        credentials: 'include'
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await j(r);
      setUploadedDoc(data.document || data); // be flexible with shape
    } catch (e) {
      alert('Upload failed: ' + e.message);
    } finally {
      setUploading(false);
    }
  };

  // create a SIMPLE ad-hoc stamp (server will create-or-reuse a default if needed)
  const onStamp = async () => {
    if (!uploadedDoc?._id) return alert('Please upload a PDF first.');
    setStamping(true);
    setResult(null);
    try {
      const payload = {
        documentId: uploadedDoc._id,
        page: Number(page),
        x: Number(x),
        y: Number(y),
        scale: Number(scale),
        opacity: Number(opacity),
        // “lightweight” design – your server route will accept text/color or use default
        design: { text: stampText || 'APPROVED' }
      };
      const r = await api.post('/stamps/apply', {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await j(r);
      setResult(data); // {downloadUrl? or s3SignedUrl?, id}
    } catch (e) {
      alert('Stamp failed: ' + e.message);
    } finally {
      setStamping(false);
    }
  };

  const onVerifyV2 = async (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    setVerifying(true);
    setVerifyOk(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await api.post('/verify/v2', { body: fd, credentials: 'include' });
      const data = await j(r);
      setVerifyOk(Boolean(data.ok));
      if (!r.ok) throw new Error(data.error || 'verify_failed');
    } catch (e) {
      setVerifyOk(false);
      alert('Verify failed: ' + e.message);
    } finally {
      setVerifying(false);
    }
  };

  const loadAudit = async () => {
    try {
      const r = await api.get('/audit/my?limit=50', { credentials: 'include' });
      const data = await j(r);
      setAudit(data.items || []);
    } catch (e) {
      alert('Load audit failed: ' + e.message);
    }
  };

  return (
    <div style={{ maxWidth: 1000, margin: '24px auto', fontFamily: 'ui-sans-serif, system-ui' }}>
      <h1>eStamp Pro — Dashboard</h1>

      {/* Auth */}
      <section style={card}>
        <h2>Auth</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="email" style={input} />
          <input value={password} onChange={e => setPassword(e.target.value)} placeholder="password" type="password" style={input} />
          <button onClick={onRegister}>Register</button>
          <button onClick={onLogin}>Login</button>
          <button onClick={onLogout}>Logout</button>
        </div>
        <p style={{ marginTop: 8 }}>
          {me ? <>Logged in as <b>{me.email}</b></> : 'Not logged in'}
        </p>
      </section>

      {/* Upload */}
      <section style={card}>
        <h2>Upload PDF</h2>
        <input type="file" accept="application/pdf" onChange={onUpload} disabled={uploading} />
        {uploadedDoc && (
          <p style={{ marginTop: 8 }}>
            Uploaded: <code>{uploadedDoc._id}</code>
          </p>
        )}
      </section>

      {/* Stamp */}
      <section style={card}>
        <h2>Stamp PDF</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8, maxWidth: 700 }}>
          <label>Page<input style={input} value={page} onChange={e => setPage(e.target.value)} /></label>
          <label>X<input style={input} value={x} onChange={e => setX(e.target.value)} /></label>
          <label>Y<input style={input} value={y} onChange={e => setY(e.target.value)} /></label>
          <label>Scale<input style={input} value={scale} onChange={e => setScale(e.target.value)} /></label>
          <label>Opacity<input style={input} value={opacity} onChange={e => setOpacity(e.target.value)} /></label>
          <label>Text<input style={input} value={stampText} onChange={e => setStampText(e.target.value)} placeholder="APPROVED" /></label>
        </div>
        <div style={{ marginTop: 8 }}>
          <button onClick={onStamp} disabled={stamping || !uploadedDoc}>Apply Stamp</button>
        </div>

        {result && (
          <div style={{ marginTop: 10 }}>
            <b>Result:</b>{' '}
            {result.downloadUrl && <a href={result.downloadUrl}>download</a>}
            {(!result.downloadUrl && result.s3SignedUrl) && <a href={result.s3SignedUrl}>download (S3)</a>}
            {(!result.downloadUrl && !result.s3SignedUrl && result.id) && (
              <a href={`/download/${result.id}`}>download</a>
            )}
          </div>
        )}
      </section>

      {/* Verify v2 */}
      <section style={card}>
        <h2>Verify (Password-Free, v2)</h2>
        <input type="file" accept="application/pdf" onChange={onVerifyV2} disabled={verifying} />
        {verifyOk != null && (
          <p style={{ marginTop: 8 }}>
            Result: <b>{verifyOk ? 'OK' : 'FAILED'}</b>
          </p>
        )}
      </section>

      {/* Audit */}
      <section style={card}>
        <h2>Audit Log</h2>
        <button onClick={loadAudit}>Load My Audit (latest 50)</button>
        <table style={{ width: '100%', marginTop: 12, borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <Th>Time</Th><Th>Action</Th><Th>OK</Th><Th>Target</Th><Th>Meta</Th><Th>IP</Th><Th>UA</Th>
            </tr>
          </thead>
          <tbody>
            {audit.map((r) => (
              <tr key={r._id}>
                <Td>{r.time ? new Date(r.time).toLocaleString() : '—'}</Td>
                <Td>{r.action ?? '—'}</Td>
                <Td>{String(r.ok ?? '—')}</Td>
                <Td>{String(r.target ?? '—')}</Td>
                <Td><code>{JSON.stringify(r.meta ?? {})}</code></Td>
                <Td>{r.ip ?? '—'}</Td>
                <Td>{r.ua ?? '—'}</Td>
              </tr>
            ))}
            {!audit.length && (
              <tr><Td colSpan={7} style={{ textAlign: 'center', color: '#666' }}>No audit rows yet.</Td></tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}

// simple styles
const card = { padding: 16, border: '1px solid #e5e7eb', borderRadius: 8, marginBottom: 16 };
const input = { padding: 8, border: '1px solid #e5e7eb', borderRadius: 6, width: '100%' };

const Th = (p) => <th style={{ textAlign: 'left', borderBottom: '1px solid #eee', padding: '6px 4px' }} {...p} />;
const Td = (p) => <td style={{ borderBottom: '1px solid #f3f4f6', padding: '6px 4px' }} {...p} />;
