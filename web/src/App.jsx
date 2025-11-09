import React, { useEffect, useState } from 'react';
import api from './api';

export default function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [me, setMe] = useState(null);
  const [audit, setAudit] = useState([]);
  const [busy, setBusy] = useState(false);

  // sanity ping (helpful during deploys)
  useEffect(() => { api.get('/health').catch(() => {}); }, []);

  async function register() {
    try {
      setBusy(true);
      const { data } = await api.post('/auth/register', { email, password });
      alert(data?.ok ? 'Registered' : 'Register failed');
    } catch (e) {
      alert(errMsg(e));
    } finally { setBusy(false); }
  }

  async function login() {
    try {
      setBusy(true);
      const { data } = await api.post('/auth/login', { email, password });
      if (data?.token) localStorage.setItem('access_token', data.token);
      const meResp = await api.get('/auth/me');
      setMe(meResp.data?.user || null);
      alert('Logged in');
    } catch (e) {
      alert(errMsg(e));
    } finally { setBusy(false); }
  }

  async function logout() {
    await api.post('/auth/logout').catch(() => {});
    localStorage.removeItem('access_token');
    setMe(null);
    setAudit([]);
  }

  async function loadAudit() {
    try {
      setBusy(true);
      const { data } = await api.get('/audit/my', { params: { limit: 50 } });
      setAudit(data?.items || []);
    } catch (e) {
      alert(errMsg(e));
    } finally { setBusy(false); }
  }

  return (
    <div style={{ maxWidth: 950, margin: '32px auto', fontFamily: 'system-ui, sans-serif' }}>
      <h1>eStamp Pro — Demo</h1>

      <section style={card}>
        <h2>Auth</h2>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="email" />
          <input value={password} onChange={e => setPassword(e.target.value)} type="password" placeholder="password" />
          <button disabled={busy} onClick={register}>Register</button>
          <button disabled={busy} onClick={login}>Login</button>
          <button disabled={busy} onClick={logout}>Logout</button>
        </div>
        <div style={{ marginTop: 10 }}>
          {me ? <b>Logged in as {me.email}</b> : <span>Not logged in</span>}
        </div>
      </section>

      <section style={card}>
        <h2>Audit Log</h2>
        <button disabled={busy} onClick={loadAudit}>Load My Audit (latest 50)</button>
        <table style={{ width: '100%', marginTop: 10, borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>Time</th>
              <th style={th}>Action</th>
              <th style={th}>OK</th>
              <th style={th}>Target</th>
              <th style={th}>Meta</th>
              <th style={th}>IP</th>
              <th style={th}>UA</th>
            </tr>
          </thead>
          <tbody>
            {audit.length === 0 && <tr><td style={td} colSpan="7">No audit rows yet.</td></tr>}
            {audit.map((r, i) => (
              <tr key={i}>
                <td style={td}>{new Date(r.createdAt || r.timestamp).toLocaleString()}</td>
                <td style={td}>{r.action || '—'}</td>
                <td style={td}>{String(r.ok)}</td>
                <td style={td}>{r.target || '—'}</td>
                <td style={td}><code style={{ fontSize: 12 }}>{JSON.stringify(r.meta || {})}</code></td>
                <td style={td}>{r.ip || '—'}</td>
                <td style={td}>{(r.ua || '').slice(0, 40)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

const card = { padding: 16, border: '1px solid #ddd', borderRadius: 8, marginBottom: 20, background: '#fff' };
const th = { textAlign: 'left', borderBottom: '1px solid #e5e5e5', padding: '6px 8px' };
const td = { padding: '6px 8px', borderBottom: '1px dashed #f0f0f0' };

function errMsg(e) {
  return e?.response?.data?.error || e?.message || 'Request failed';
}
