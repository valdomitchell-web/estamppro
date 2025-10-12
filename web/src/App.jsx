
import React, { useState } from 'react'
import axios from 'axios'
import { jwtDecode } from 'jwt-decode'
import StampDesigner from './StampDesigner.jsx'

const API = import.meta.env.VITE_API || 'http://localhost:4000'

function showErr(e) {
  const msg = e?.response?.data?.error || e?.message || String(e)
  alert('Error: ' + msg)
  console.error(e)
}

export default function App() {
  // --- STATE (declare before any usage)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(null)

  const [docId, setDocId] = useState('')
  const [stampId, setStampId] = useState('')
  const [stamps, setStamps] = useState([])

  const [pos, setPos] = useState({ page: 0, x: 50, y: 50, scale: 0.5, opacity: 0.9 })
  const [downloadUrl, setDownloadUrl] = useState('')
  const [mfaStageToken, setMfaStageToken] = useState('')
  const [qrDataUrl, setQrDataUrl] = useState('')
  const [backupCodes, setBackupCodes] = useState([])
  const [rememberDevice, setRememberDevice] = useState(true)

  const authHeader = () => (token ? { Authorization: `Bearer ${token}` } : {})

  // --- AUTH
  async function register() {
    try {
      const { data } = await axios.post(`${API}/auth/register`, { email, password }, { withCredentials: true })
      setToken(data.token)
      alert('Registered. (Optional) Set up MFA below.')
    } catch (e) { showErr(e) }
  }

  async function login() {
    try {
      const { data } = await axios.post(`${API}/auth/login`, { email, password }, { withCredentials: true })
      if (data.mfa_required) { setMfaStageToken(data.token); alert('MFA required. Enter TOTP or backup.'); return }
      setToken(data.token); alert('Logged in.')
    } catch (e) { showErr(e) }
  }

  async function refreshSession() {
    try {
      const { data } = await axios.post(`${API}/auth/refresh`, {}, { withCredentials: true })
      setToken(data.token); alert('Session refreshed.')
    } catch (e) { showErr(e) }
  }

  async function logout() {
    try {
      await axios.post(`${API}/auth/logout`, {}, { withCredentials: true })
      setToken(null); alert('Logged out.')
    } catch (e) { showErr(e) }
  }

  // --- MFA
  async function startMfaSetup() {
    try {
      const { data } = await axios.post(`${API}/auth/mfa/setup`, {}, { headers: authHeader(), withCredentials: true })
      setQrDataUrl(data.qr); alert('Scan QR, then Verify.')
    } catch (e) { showErr(e) }
  }
  async function verifyMfaSetup() {
    try {
      const code = prompt('Enter 6-digit code from your Authenticator')
      const { data } = await axios.post(`${API}/auth/mfa/verify`, { code }, { headers: authHeader(), withCredentials: true })
      setBackupCodes(data.backup_codes || []); alert('MFA enabled. Save backup codes!')
    } catch (e) { showErr(e) }
  }
  async function finishMfaWithTotp() {
    const code = prompt('Enter 6-digit TOTP')
    try {
      const { data } = await axios.post(`${API}/auth/mfa/login`, { token: mfaStageToken, code, remember: rememberDevice }, { withCredentials: true })
      setToken(data.token); setMfaStageToken(''); alert('Logged in (MFA).')
    } catch (e) { showErr(e) }
  }
  async function finishMfaWithBackup() {
    const backup = prompt('Enter backup code')
    try {
      const { data } = await axios.post(`${API}/auth/mfa/login`, { token: mfaStageToken, backup, remember: rememberDevice }, { withCredentials: true })
      setToken(data.token); setMfaStageToken(''); alert('Logged in (backup).')
    } catch (e) { showErr(e) }
  }

  // --- DOCS & STAMPS
  async function uploadPdf(e) {
    try {
      const f = e.target.files[0]; if (!f) return
      const form = new FormData(); form.append('file', f)
      const { data } = await axios.post(`${API}/documents/upload`, form, { headers: { ...authHeader(), 'Content-Type': 'multipart/form-data' } })
      setDocId(data.document?.id || ''); alert('Uploaded PDF. Document ID: ' + (data.document?.id || '(none)'))
    } catch (e) { showErr(e) }
  }
  async function createStamp(e) {
    try {
      const f = e.target.files[0]; if (!f) return
      const name = prompt('Stamp name?') || 'My Stamp'
      const pw = prompt('Set a stamp password'); if (!pw) return alert('Password required')
      const form = new FormData()
      form.append('image', f); form.append('name', name); form.append('password', pw)
      const { data } = await axios.post(`${API}/stamps`, form, { headers: { ...authHeader(), 'Content-Type': 'multipart/form-data' } })
      alert('Created stamp: ' + data.stamp?.name); await listStamps()
    } catch (e) { showErr(e) }
  }
  async function listStamps() {
    try {
      const { data } = await axios.get(`${API}/stamps`, { headers: authHeader() })
      setStamps(data.stamps || []); if (!data.stamps?.length) alert('No stamps yet. Create one first.')
    } catch (e) { showErr(e) }
  }
  async function applyStamp() {
    try {
      const pw = prompt('Enter stamp password to unlock:'); if (!pw) return
      const body = { documentId: docId, ...pos, password: pw }
      const { data } = await axios.post(`${API}/stamps/${stampId}/apply`, body, { headers: authHeader() })
      if (data.downloadPath) setDownloadUrl(`${API}${data.downloadPath}`)
      alert('Stamped!')
    } catch (e) { showErr(e) }
  }
  async function verifyStampedPDF(e) {
    try {
      const f = e.target.files[0]; if (!f) return
      const pw = prompt('Enter the stamp password used when stamping (MVP)')
      const form = new FormData(); form.append('file', f); form.append('password', pw || '')
      const { data } = await axios.post(`${API}/verify`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
      alert('Verification: ' + JSON.stringify(data))
    } catch (e) { showErr(e) }
  }
  async function verifyPublic(e) {
    try {
      const f = e.target.files[0]; if (!f) return
      const form = new FormData(); form.append('file', f)
      const { data } = await axios.post(`${API}/verify-public`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
      alert('Public verification: ' + JSON.stringify(data))
    } catch (e) { showErr(e) }
  }

  return (
    <div style={{ fontFamily: 'sans-serif', maxWidth: 900, margin: '30px auto' }}>
      <h1>eStamp Pro — MVP</h1>

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Auth</h2>
        <input placeholder='email' value={email} onChange={e=>setEmail(e.target.value)} />
        <input placeholder='password' type='password' value={password} onChange={e=>setPassword(e.target.value)} />
        <button onClick={register}>Register</button>
        <button onClick={login}>Login</button>
        <div style={{marginTop:8}}>
          {token ? `Logged in as ${(() => { try { return jwtDecode(token).email } catch { return 'unknown' } })()}` : 'Not logged in'}
        </div>
        {token ? (
          <div style={{marginTop:8}}>
            <button onClick={refreshSession}>Refresh session</button>
            <button onClick={logout} style={{marginLeft:8}}>Logout</button>
          </div>
        ) : null}
      </section>

      {/* MFA */}
      <section style={{ border:'1px solid #ddd', padding:16, borderRadius:8, marginBottom:16 }}>
        <h2>MFA</h2>
        {!token ? (
          <div>Login to set up MFA.</div>
        ) : (
          <>
            <button onClick={startMfaSetup}>Start MFA Setup</button>
            {qrDataUrl && <div style={{marginTop:8}}><img src={qrDataUrl} alt="MFA QR" style={{width:200,height:200}} /></div>}
            <div style={{marginTop:8}}>
              <button onClick={verifyMfaSetup}>Verify & Enable MFA</button>
            </div>
            {backupCodes.length > 0 && (
              <div style={{marginTop:12}}>
                <strong>Backup codes (store securely):</strong>
                <ul>{backupCodes.map((c,i)=><li key={i}><code>{c}</code></li>)}</ul>
              </div>
            )}
          </>
        )}
        {mfaStageToken && (
          <div style={{marginTop:12}}>
            <h3>Finish Login (MFA Required)</h3>
            <label style={{display:'inline-block',marginRight:12}}>
              <input type="checkbox" checked={rememberDevice} onChange={e=>setRememberDevice(e.target.checked)} /> Remember this device for 30 days
            </label>
            <button onClick={finishMfaWithTotp}>Use TOTP code</button>
            <button style={{marginLeft:8}} onClick={finishMfaWithBackup}>Use backup code</button>
          </div>
        )}
      </section>

      {/* Designer (only when logged in) */}
      {token && (
        <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
          <StampDesigner API={API} authHeader={authHeader} />
        </section>
      )}

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Upload PDF</h2>
        <input type='file' accept='application/pdf' onChange={uploadPdf} />
        <div>Document ID: {docId || '(none yet)'}</div>
      </section>

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Create Stamp (PNG)</h2>
        <input type='file' accept='image/png' onChange={createStamp} />
        <button onClick={listStamps}>List My Stamps</button>
        <ul>
          {stamps.map(s => (
            <li key={s._id}>
              <label><input type='radio' name='stamp' onChange={()=>setStampId(s._id)} /> {s.name} ({s._id})</label>
            </li>
          ))}
        </ul>
        <div>Selected stamp: {stampId || '(none)'}</div>
      </section>

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Apply Stamp</h2>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:8, maxWidth:600 }}>
          <label>Page <input type='number' value={pos.page} onChange={e=>setPos(p=>({...p, page:+e.target.value||0}))} /></label>
          <label>X    <input type='number' value={pos.x}    onChange={e=>setPos(p=>({...p, x:+e.target.value||0}))} /></label>
          <label>Y    <input type='number' value={pos.y}    onChange={e=>setPos(p=>({...p, y:+e.target.value||0}))} /></label>
          <label>Scale  <input type='number' step='0.1' value={pos.scale}  onChange={e=>setPos(p=>({...p, scale:+e.target.value||0.1}))} /></label>
          <label>Opacity<input type='number' step='0.1' min='0' max='1' value={pos.opacity} onChange={e=>setPos(p=>({...p, opacity: Math.max(0, Math.min(1, +e.target.value||1))}))} /></label>
        </div>
        <div style={{ marginTop: 12 }}>
          <button disabled={!docId || !stampId} onClick={applyStamp}>Apply</button>
        </div>
        {downloadUrl && (
          <div style={{ marginTop: 8 }}>
            <a href={downloadUrl} target="_blank" rel="noreferrer">
              <button>Download last stamped PDF</button>
            </a>
          </div>
        )}
        <small>Note: PDF coordinates are from the bottom-left corner.</small>
      </section>

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Verify Stamped PDF (v1 password)</h2>
        <input type='file' accept='application/pdf' onChange={verifyStampedPDF} />
      </section>

      <section style={{ border:'1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h2>Verify (Password-Free, v2)</h2>
        <input type='file' accept='application/pdf' onChange={verifyPublic} />
        <small style={{display:'block',marginTop:6}}>Public key: <a href={`${API}/public-key`} target="_blank" rel="noreferrer">/public-key</a></small>
      </section>
    </div>
  )
}
