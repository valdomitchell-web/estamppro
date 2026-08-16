import React, { useState } from "react";
import PublicHeader from "./PublicHeader.jsx";
import PublicFooter from "./PublicFooter.jsx";
import HeroSection from "./HeroSection.jsx";

const sectionStyle = { maxWidth: 1120, margin: "0 auto", padding: "88px 24px" };
const headingStyle = { margin: "0 0 16px", color: "#0f172a", fontSize: "clamp(32px, 5vw, 48px)", lineHeight: 1.08, letterSpacing: "-1px" };
const textStyle = { color: "#64748b", fontSize: 17, lineHeight: 1.75 };
const primaryButton = { display: "inline-flex", alignItems: "center", justifyContent: "center", background: "#1d4ed8", color: "#ffffff", textDecoration: "none", padding: "14px 20px", borderRadius: 12, fontWeight: 900, boxShadow: "0 12px 28px rgba(29,78,216,0.22)" };
const secondaryButton = { ...primaryButton, background: "#ffffff", color: "#1d4ed8", border: "1px solid #bfdbfe", boxShadow: "none" };

export default function HomePage() {
  return (
    <div style={{ minHeight: "100vh", background: "#ffffff", color: "#0f172a" }}>
      <PublicHeader />
      <HeroSection />
      <TrustBar />
      <StatsSection />
      <FeatureSection />
      <HowItWorksSection />
      <UseCasesSection />
<FAQSection />
      <FinalCTA />
      <PublicFooter />
    </div>
  );
}

function TrustBar() {
  const items = [["✓", "QR Verification"], ["◈", "Digital Certificates"], ["◎", "Audit Trails"], ["♙", "Team Collaboration"], ["⌁", "API Integration"], ["✦", "Business Branding"]];
  return <section style={{ background: "#0f172a", color: "#ffffff" }}><div style={{ maxWidth: 1120, margin: "0 auto", padding: "22px 24px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12 }}>{items.map(([icon,label]) => <div key={label} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 9, padding: "10px 12px", borderRadius: 999, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)", fontWeight: 800, fontSize: 14, textAlign: "center" }}><span style={{ color: "#93c5fd" }}>{icon}</span>{label}</div>)}</div></section>;
}

function StatsSection() {
  const stats = [["Instant", "Document verification"], ["24/7", "Secure cloud access"], ["Secure", "Encrypted transport"], ["3 plans", "Built to scale"]];
  return <section style={{ background: "#f8fafc" }}><div style={{ ...sectionStyle, paddingTop: 56, paddingBottom: 56, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 18 }}>{stats.map(([value,label]) => <div key={label} style={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 18, padding: 24, textAlign: "center", boxShadow: "0 10px 26px rgba(15,23,42,0.05)" }}><div style={{ fontSize: 32, fontWeight: 950, color: "#1d4ed8" }}>{value}</div><div style={{ marginTop: 8, color: "#64748b", fontWeight: 750 }}>{label}</div></div>)}</div></section>;
}

function FeatureSection() {
  const features = [["◫","Secure PDF Stamping","Apply professional electronic stamps to PDFs with precise placement and reusable designs."],["⌁","QR Verification","Every stamped document can link to a public verification page for fast authenticity checks."],["▣","Digital Certificates","Generate downloadable certificates that clearly document verification details."],["◎","Audit & Analytics","Track stamping, sharing, verification, opens, clicks, and team activity in one place."],["♙","Team Workflows","Invite staff, assign roles, and keep organization access controlled and accountable."],["⚡","API Access","Connect eStamp Pro to your own business systems and automate document workflows."]];
  return <section id="features" style={{ background: "#ffffff" }}><div style={sectionStyle}><div style={{ maxWidth: 740, marginBottom: 42 }}><div style={{ color: "#1d4ed8", fontWeight: 900, marginBottom: 10 }}>EVERYTHING YOU NEED</div><h2 style={headingStyle}>A complete document trust platform</h2><p style={textStyle}>From the first stamp to the final verification, eStamp Pro gives your organization the tools to create professional, traceable document workflows.</p></div><div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 20 }}>{features.map(([icon,title,text]) => <article key={title} style={{ background: "linear-gradient(180deg, #ffffff 0%, #f8fbff 100%)", border: "1px solid #dbeafe", borderRadius: 20, padding: 26, boxShadow: "0 12px 30px rgba(15,23,42,0.06)" }}><div style={{ width: 48, height: 48, borderRadius: 14, background: "#dbeafe", color: "#1d4ed8", display: "grid", placeItems: "center", fontSize: 24, marginBottom: 18 }}>{icon}</div><h3 style={{ margin: "0 0 10px", fontSize: 21 }}>{title}</h3><p style={{ ...textStyle, margin: 0, fontSize: 15.5 }}>{text}</p></article>)}</div></div></section>;
}

function HowItWorksSection() {
  const steps = [["01","Upload your PDF","Add one document or a full batch of PDFs."],["02","Apply your stamp","Choose a saved stamp, place it, and adjust it visually."],["03","Share securely","Send stamped documents with tracked delivery and professional branding."],["04","Verify instantly","Recipients scan the QR code or open the verification page."]];
  return <section style={{ background: "#eff6ff" }}><div style={sectionStyle}><div style={{ maxWidth: 720, marginBottom: 42 }}><div style={{ color: "#1d4ed8", fontWeight: 900, marginBottom: 10 }}>HOW IT WORKS</div><h2 style={headingStyle}>From PDF to verified proof in four steps</h2></div><div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 18 }}>{steps.map(([number,title,text]) => <div key={number} style={{ background: "#ffffff", border: "1px solid #bfdbfe", borderRadius: 18, padding: 24 }}><div style={{ color: "#1d4ed8", fontWeight: 950, fontSize: 14 }}>STEP {number}</div><h3 style={{ margin: "14px 0 10px", fontSize: 20 }}>{title}</h3><p style={{ ...textStyle, margin: 0, fontSize: 15 }}>{text}</p></div>)}</div></div></section>;
}

function UseCasesSection() {
  const uses = ["Administrators and corporate offices","Compliance and verification teams","Legal and professional services","Construction and field operations","Education and certification workflows","Small businesses and service providers"];
  return <section style={{ background: "#ffffff" }}><div style={{ ...sectionStyle, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 42, alignItems: "center" }}><div><div style={{ color: "#1d4ed8", fontWeight: 900, marginBottom: 10 }}>BUILT FOR REAL WORKFLOWS</div><h2 style={headingStyle}>Professional document trust for every team</h2><p style={textStyle}>Whether your organization handles approvals, certificates, invoices, compliance records, or client documentation, eStamp Pro keeps the process consistent and verifiable.</p><a href="/features" style={secondaryButton}>Explore all features</a></div><div style={{ background: "#0f172a", borderRadius: 24, padding: 28, boxShadow: "0 20px 50px rgba(15,23,42,0.18)" }}>{uses.map(item => <div key={item} style={{ display: "flex", gap: 12, alignItems: "center", color: "#e2e8f0", padding: "14px 0", borderBottom: "1px solid rgba(255,255,255,0.08)" }}><span style={{ color: "#60a5fa", fontWeight: 900 }}>✓</span><span style={{ fontWeight: 750 }}>{item}</span></div>)}</div></div></section>;
}

function TestimonialsSection() {
  const quotes = [["“eStamp Pro makes document verification feel simple and professional.”","Operations team"],["“The QR verification flow gives recipients confidence immediately.”","Business administrator"],["“We can stamp, share, and review activity without juggling multiple tools.”","Compliance workflow user"]];
  return <section style={{ background: "#f8fafc" }}><div style={sectionStyle}><div style={{ textAlign: "center", maxWidth: 720, margin: "0 auto 40px" }}><div style={{ color: "#1d4ed8", fontWeight: 900, marginBottom: 10 }}>BUILT FOR CONFIDENCE</div><h2 style={headingStyle}>A more trustworthy way to handle documents</h2></div><div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 20 }}>{quotes.map(([quote,role]) => <blockquote key={role} style={{ margin: 0, background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 20, padding: 26, boxShadow: "0 10px 28px rgba(15,23,42,0.05)" }}><div style={{ color: "#f59e0b", letterSpacing: 3, marginBottom: 16 }}>★★★★★</div><p style={{ ...textStyle, color: "#334155", fontSize: 17 }}>{quote}</p><div style={{ color: "#64748b", fontWeight: 800 }}>{role}</div></blockquote>)}</div></div></section>;
}

function FAQSection() {
  const faqs = [["Can anyone verify a stamped document?","Yes. Recipients can use the QR code or public verification page without needing an eStamp Pro account."],[
  "Can I upload my own business stamp?",
  "Yes. Eligible plans can upload a custom business stamp, and eStamp Pro also includes tools for creating professional stamp designs."
],,["Can I cancel my subscription?","Yes. PayPal subscriptions can be cancelled from eStamp Pro, with access continuing through the paid period."],["Is eStamp Pro suitable for teams?","Yes. Business plans include role-based team access, API keys, advanced branding, and signature placement."],["Does eStamp Pro support audit trails?","Yes. Stamping, sharing, verification, team, login, and API activity can be recorded for review."]];
  const [open,setOpen] = useState(0);
  return <section style={{ background: "#ffffff" }}><div style={{ ...sectionStyle, maxWidth: 900 }}><div style={{ textAlign: "center", marginBottom: 36 }}><div style={{ color: "#1d4ed8", fontWeight: 900, marginBottom: 10 }}>FREQUENTLY ASKED QUESTIONS</div><h2 style={headingStyle}>Questions before you get started?</h2></div><div style={{ display: "grid", gap: 12 }}>{faqs.map(([question,answer],index) => <button key={question} type="button" onClick={() => setOpen(open === index ? -1 : index)} style={{ textAlign: "left", background: open === index ? "#eff6ff" : "#ffffff", border: "1px solid #dbeafe", borderRadius: 16, padding: "18px 20px", cursor: "pointer" }}><div style={{ display: "flex", justifyContent: "space-between", gap: 20, alignItems: "center", fontWeight: 900, color: "#0f172a", fontSize: 17 }}>{question}<span style={{ color: "#1d4ed8", fontSize: 22 }}>{open === index ? "−" : "+"}</span></div>{open === index && <div style={{ ...textStyle, fontSize: 15.5, marginTop: 12 }}>{answer}</div>}</button>)}</div></div></section>;
}

function FinalCTA() {
  return <section style={{ padding: "40px 24px 88px", background: "#ffffff" }}><div style={{ maxWidth: 1120, margin: "0 auto", background: "linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%)", borderRadius: 28, padding: "58px 28px", textAlign: "center", color: "#ffffff", boxShadow: "0 24px 60px rgba(29,78,216,0.25)" }}><h2 style={{ margin: "0 0 14px", fontSize: "clamp(32px, 5vw, 48px)" }}>Build trust into your next document</h2><p style={{ margin: "0 auto 28px", maxWidth: 680, color: "#dbeafe", fontSize: 18 }}>Start free, create your organization when you are ready, and upgrade only when your workflow grows.</p><div style={{ display: "flex", justifyContent: "center", gap: 12, flexWrap: "wrap" }}><a href="https://app.estamppro.com/?auth=register&fresh=1" style={{ ...primaryButton, background: "#ffffff", color: "#1d4ed8" }}>Start Free</a><a href="/pricing" style={{ ...secondaryButton, background: "transparent", color: "#ffffff", borderColor: "rgba(255,255,255,0.45)" }}>View Pricing</a></div></div></section>;
}