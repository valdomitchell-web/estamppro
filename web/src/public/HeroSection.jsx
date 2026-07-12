import React from "react";

export default function HeroSection() {
  return (
    <section style={{ position: "relative", overflow: "hidden", background: "radial-gradient(circle at 15% 20%, rgba(59,130,246,0.18), transparent 28%), radial-gradient(circle at 85% 25%, rgba(96,165,250,0.14), transparent 26%), linear-gradient(135deg, #eff6ff 0%, #ffffff 50%, #f8fafc 100%)", padding: "92px 24px 84px" }}>
      <div style={{ position: "absolute", width: 320, height: 320, borderRadius: "50%", background: "rgba(37,99,235,0.08)", filter: "blur(8px)", top: -120, right: -80 }} />
      <div style={{ maxWidth: 1120, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(330px, 1fr))", gap: 52, alignItems: "center", position: "relative", zIndex: 1 }}>
        <div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "#dbeafe", color: "#1d4ed8", border: "1px solid #bfdbfe", padding: "8px 14px", borderRadius: 999, fontWeight: 900, marginBottom: 22 }}><span>●</span>Document Trust Platform</div>
          <h1 style={{ fontSize: "clamp(48px, 7vw, 72px)", lineHeight: 0.98, margin: "0 0 24px", color: "#0f172a", letterSpacing: "-2.5px", maxWidth: 720 }}>Build trust into every document</h1>
          <p style={{ fontSize: 19, lineHeight: 1.75, color: "#475569", maxWidth: 650, marginBottom: 30 }}>Securely stamp, certify, share, and verify PDF documents with QR verification, digital certificates, analytics, and professional audit trails.</p>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
            <a href="https://app.estamppro.com/?auth=register&fresh=1" style={{ background: "#1d4ed8", color: "#fff", textDecoration: "none", padding: "15px 22px", borderRadius: 12, fontWeight: 900, boxShadow: "0 14px 32px rgba(29,78,216,0.25)" }}>Start Free</a>
            <a href="/pricing" style={{ background: "#ffffff", color: "#1d4ed8", textDecoration: "none", padding: "15px 22px", borderRadius: 12, fontWeight: 900, border: "1px solid #bfdbfe" }}>View Pricing</a>
          </div>
          <div style={{ marginTop: 26, display: "flex", gap: 18, flexWrap: "wrap", color: "#64748b", fontWeight: 750, fontSize: 14 }}><span>✓ No credit card required</span><span>✓ Free plan available</span><span>✓ Cancel anytime</span></div>
        </div>

        <div style={{ background: "rgba(255,255,255,0.92)", border: "1px solid #dbeafe", borderRadius: 28, padding: 24, boxShadow: "0 28px 70px rgba(15,23,42,0.14)", backdropFilter: "blur(10px)" }}>
          <div style={{ background: "#0f172a", borderRadius: 20, padding: 22, color: "#ffffff" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 18 }}><div><div style={{ fontWeight: 900, fontSize: 18 }}>Verified Document</div><div style={{ color: "#94a3b8", fontSize: 13 }}>Official electronic stamp</div></div><div style={{ background: "#dcfce7", color: "#166534", borderRadius: 999, padding: "7px 11px", fontWeight: 900, fontSize: 12 }}>✓ VERIFIED</div></div>
            <div style={{ background: "#ffffff", color: "#0f172a", borderRadius: 16, padding: 20 }}>
              <div style={{ height: 10, width: "70%", background: "#e2e8f0", borderRadius: 999, marginBottom: 12 }} />
              <div style={{ height: 10, width: "92%", background: "#e2e8f0", borderRadius: 999, marginBottom: 12 }} />
              <div style={{ height: 10, width: "84%", background: "#e2e8f0", borderRadius: 999, marginBottom: 24 }} />
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 18, alignItems: "end" }}>
                <div style={{ border: "3px solid #1d4ed8", borderRadius: "50%", width: 120, height: 120, display: "grid", placeItems: "center", textAlign: "center", fontWeight: 950, color: "#1d4ed8", fontSize: 13 }}>OFFICIAL<br />eSTAMP<br />VERIFIED</div>
                <div style={{ width: 88, height: 88, background: "linear-gradient(90deg,#0f172a 12%,transparent 12% 24%,#0f172a 24% 36%,transparent 36% 48%,#0f172a 48% 60%,transparent 60% 72%,#0f172a 72%)", border: "8px solid #ffffff", outline: "1px solid #cbd5e1" }} />
              </div>
            </div>
          </div>
          <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>{["Stamp", "Verify", "Certificate"].map(item => <div key={item} style={{ background: "#eff6ff", border: "1px solid #dbeafe", borderRadius: 12, padding: "12px 8px", textAlign: "center", color: "#1d4ed8", fontWeight: 850, fontSize: 13 }}>{item}</div>)}</div>
        </div>
      </div>
    </section>
  );
}