import React, { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "./api";

function joinUrl(base, relativePath) {
  if (!relativePath) return "";
  if (/^https?:\/\//i.test(relativePath)) return relativePath;
  const cleanBase = String(base || "").replace(/\/$/, "");
  const cleanPath = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${cleanBase}${cleanPath}`;
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString("en-US", {
    timeZone: "America/Grenada",
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
    timeZoneName: "short",
  });
}

export default function VerifyPage() {
  const { code } = useParams();
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const [technicalOpen, setTechnicalOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const loadVerification = async () => {
      try {
        const response = await api.get(
          `/verify/public?code=${encodeURIComponent(code)}`,
          { headers: { Accept: "application/json" } }
        );

        if (!cancelled) {
          setResult(response.data || null);
          setErr("");
        }
      } catch (error) {
        if (!cancelled) {
          const data = error?.response?.data;
          setErr(data?.detail || data?.error || "This document could not be verified.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    loadVerification();
    return () => {
      cancelled = true;
    };
  }, [code]);

  const verified = !!result?.verified;
  const details = result?.details || {};
  const verification = details?.verification || {};
  const payload = verification?.payload || {};
  const branding = result?.branding || {};
  const apiBase = api?.defaults?.baseURL || "";
  const certificateUrl = joinUrl(apiBase, result?.certificate_url);
  const emailTemplateUrl = joinUrl(apiBase, result?.email_template_url);

  const theme = useMemo(
    () => ({
      primary: branding?.primary_color || "#1d4ed8",
      accent: branding?.accent_color || "#0f172a",
      label: branding?.stamp_label || "Official eStamp",
      orgName: branding?.org_name || "eStamp Pro",
      tagline: branding?.verification_tagline || "Digital verification you can trust",
      footer: branding?.email_footer || "Verified securely by eStamp Pro",
      logo: branding?.logo_url || "",
      supportEmail: branding?.support_email || "",
      websiteUrl: branding?.website_url || "",
    }),
    [branding]
  );

  const verificationCode = code || payload?.verify_code || "—";
  const verifiedOn = details?.timestamp || payload?.ts || null;

  const status = verified
    ? {
        label: "VERIFIED",
        title: "This document is authentic",
        message: `This document has successfully passed all integrity checks and matches ${theme.orgName}'s official digital record. No alterations were detected.`,
        color: "#166534",
        background: "#ecfdf3",
        border: "#bbf7d0",
        icon: "✓",
      }
    : {
        label: "NOT VERIFIED",
        title: "Verification could not be completed",
        message: err || "This document could not be matched to a valid eStamp record.",
        color: "#991b1b",
        background: "#fef2f2",
        border: "#fecaca",
        icon: "!",
      };

  const primaryButton = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: 46,
    padding: "0 18px",
    borderRadius: 12,
    background: theme.primary,
    color: "#ffffff",
    border: `1px solid ${theme.primary}`,
    textDecoration: "none",
    fontWeight: 900,
    boxSizing: "border-box",
  };

  const secondaryButton = {
    ...primaryButton,
    background: "#ffffff",
    color: theme.primary,
  };

  const infoCardStyle = {
    background: "#ffffff",
    border: "1px solid #dbeafe",
    borderRadius: 16,
    padding: 18,
    minHeight: 108,
    boxShadow: "0 8px 24px rgba(15,23,42,0.04)",
  };

  const infoLabelStyle = {
    fontSize: 12,
    fontWeight: 900,
    color: "#64748b",
    textTransform: "uppercase",
    letterSpacing: 0.6,
    marginBottom: 10,
  };

  const infoValueStyle = {
    fontSize: 16,
    lineHeight: 1.5,
    fontWeight: 850,
    color: "#0f172a",
    overflowWrap: "anywhere",
  };

  return (
    <main
      style={{
        minHeight: "100vh",
        background:
          "radial-gradient(circle at top left, rgba(59,130,246,0.10), transparent 30%), linear-gradient(180deg, #f8fbff 0%, #eef4fb 100%)",
        fontFamily:
          'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        color: "#0f172a",
        padding: 20,
        boxSizing: "border-box",
      }}
    >
      <div style={{ width: "100%", maxWidth: 1040, margin: "24px auto" }}>
        <section
          style={{
            position: "relative",
            background: "#ffffff",
            border: "1px solid #dbe4f0",
            borderRadius: 24,
            overflow: "hidden",
            boxShadow: "0 24px 60px rgba(15,23,42,0.10)",
          }}
        >
          <header
            style={{
              background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.accent} 100%)`,
              color: "#ffffff",
              padding: "26px 28px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 20,
              flexWrap: "wrap",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 16, minWidth: 0 }}>
              {theme.logo ? (
                <img
                  src={theme.logo}
                  alt={`${theme.orgName} logo`}
                  style={{
                    width: 72,
                    height: 72,
                    objectFit: "contain",
                    borderRadius: 16,
                    background: "rgba(255,255,255,0.12)",
                    padding: 8,
                    boxSizing: "border-box",
                    flexShrink: 0,
                  }}
                />
              ) : (
                <div
                  style={{
                    width: 72,
                    height: 72,
                    borderRadius: 16,
                    background: "rgba(255,255,255,0.14)",
                    display: "grid",
                    placeItems: "center",
                    fontSize: 30,
                    fontWeight: 950,
                    flexShrink: 0,
                  }}
                >
                  ✓
                </div>
              )}

              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontSize: 13,
                    fontWeight: 900,
                    opacity: 0.85,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                  }}
                >
                  OFFICIAL DIGITAL VERIFICATION PORTAL
                </div>
                <h1
                  style={{
                    margin: "7px 0 5px",
                    fontSize: "clamp(30px, 5vw, 44px)",
                    lineHeight: 1.02,
                    wordBreak: "break-word",
                  }}
                >
                  {theme.orgName}
                </h1>
                <div style={{ fontSize: 15, opacity: 0.95 }}>
                  Trusted document authentication and digital certificate validation
                </div>
              </div>
            </div>

            <Link
              to="/"
              style={{
                ...secondaryButton,
                color: "#ffffff",
                background: "transparent",
                borderColor: "rgba(255,255,255,0.55)",
              }}
            >
              Back to dashboard
            </Link>
          </header>

          <div style={{ padding: 28 }}>
            {loading ? (
              <div
                style={{
                  minHeight: 320,
                  display: "grid",
                  placeItems: "center",
                  textAlign: "center",
                  color: "#475569",
                }}
              >
                <div>
                  <div
                    style={{
                      width: 54,
                      height: 54,
                      borderRadius: "50%",
                      border: "5px solid #dbeafe",
                      borderTopColor: theme.primary,
                      margin: "0 auto 18px",
                    }}
                  />
                  <div style={{ fontSize: 18, fontWeight: 850 }}>
                    Checking verification record…
                  </div>
                </div>
              </div>
            ) : (
              <>
                <section
                  style={{
                    background: status.background,
                    border: `1px solid ${status.border}`,
                    borderRadius: 20,
                    padding: 28,
                    display: "grid",
                    gridTemplateColumns: "minmax(100px, 130px) minmax(0, 1fr)",
                    gap: 24,
                    alignItems: "center",
                  }}
                >
                  <div
                    style={{
                      width: 108,
                      height: 108,
                      borderRadius: "50%",
                      background: "#ffffff",
                      border: `8px solid ${status.border}`,
                      color: status.color,
                      display: "grid",
                      placeItems: "center",
                      fontSize: 48,
                      fontWeight: 950,
                      boxShadow: "0 12px 30px rgba(15,23,42,0.08)",
                    }}
                  >
                    {status.icon}
                  </div>

                  <div>
                    <div
                      style={{
                        display: "inline-flex",
                        borderRadius: 999,
                        background: "#ffffff",
                        color: status.color,
                        border: `1px solid ${status.border}`,
                        padding: "8px 14px",
                        fontWeight: 950,
                        fontSize: 13,
                        letterSpacing: 0.8,
                        marginBottom: 14,
                      }}
                    >
                      {status.label}
                    </div>
                    <h2
                      style={{
                        margin: "0 0 10px",
                        color: "#0f172a",
                        fontSize: "clamp(28px, 5vw, 42px)",
                        lineHeight: 1.08,
                      }}
                    >
                      {status.title}
                    </h2>
                    <p style={{ margin: 0, color: "#475569", fontSize: 17, lineHeight: 1.65 }}>
                      {status.message}
                    </p>

                    {verified ? (
                      <div
                        style={{
                          marginTop: 14,
                          display: "flex",
                          gap: 10,
                          flexWrap: "wrap",
                        }}
                      >
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 7,
                            background: "#ffffff",
                            border: "1px solid #bbf7d0",
                            color: "#166534",
                            borderRadius: 999,
                            padding: "7px 11px",
                            fontSize: 13,
                            fontWeight: 900,
                          }}
                        >
                          🛡 SHA-256 VERIFIED
                        </span>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 7,
                            background: "#ffffff",
                            border: "1px solid #bbf7d0",
                            color: "#166534",
                            borderRadius: 999,
                            padding: "7px 11px",
                            fontSize: 13,
                            fontWeight: 900,
                          }}
                        >
                          ✓ QR VERIFIED
                        </span>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 7,
                            background: "#ffffff",
                            border: "1px solid #bbf7d0",
                            color: "#166534",
                            borderRadius: 999,
                            padding: "8px 12px",
                            fontSize: 13,
                            fontWeight: 900,
                          }}
                        >
                          ✓ OFFICIAL STAMP
                        </span>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 7,
                            background: "#ffffff",
                            border: "1px solid #bbf7d0",
                            color: "#166534",
                            borderRadius: 999,
                            padding: "8px 12px",
                            fontSize: 13,
                            fontWeight: 900,
                          }}
                        >
                          ✓ TRUSTED CERTIFICATE
                        </span>
                      </div>
                    ) : null}
                  </div>
                </section>

                {verified ? (
                  <section
                    style={{
                      marginTop: 28,
                      border: "1px solid #dbeafe",
                      borderRadius: 18,
                      background:
                        "linear-gradient(180deg, #ffffff 0%, #f8fbff 100%)",
                      padding: "24px 26px",
                      textAlign: "center",
                      boxShadow: "0 10px 28px rgba(15,23,42,0.05)",
                    }}
                  >
                    <div
                      style={{
                        color: theme.primary,
                        fontWeight: 950,
                        fontSize: 12,
                        textTransform: "uppercase",
                        letterSpacing: 1.2,
                        marginBottom: 10,
                      }}
                    >
                      OFFICIAL DIGITAL CERTIFICATE
                    </div>
                    <div
                      style={{
                        height: 1,
                        background:
                          "linear-gradient(90deg, transparent, #bfdbfe, transparent)",
                        margin: "0 auto 16px",
                        maxWidth: 540,
                      }}
                    />
                    <div
                      style={{
                        fontSize: "clamp(22px, 4vw, 30px)",
                        fontWeight: 950,
                        color: "#0f172a",
                      }}
                    >
                      Issued by
                      <div
                        style={{
                          marginTop: 6,
                          fontSize: "clamp(28px, 5vw, 38px)",
                          fontWeight: 950,
                          letterSpacing: 0.8,
                          textTransform: "uppercase",
                        }}
                      >
                        {theme.orgName}
                      </div>
                      <div
                        style={{
                          marginTop: 6,
                          fontSize: 14,
                          fontWeight: 800,
                          color: "#64748b",
                        }}
                      >
                        Official Digital Stamp Authority
                      </div>
                    </div>
                    <div
                      style={{
                        marginTop: 10,
                        color: "#475569",
                        lineHeight: 1.7,
                      }}
                    >
                      Verified {formatDate(verifiedOn)}
                    </div>
                    <div
                      style={{
                        marginTop: 12,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 8,
                        background: "#eff6ff",
                        color: theme.primary,
                        border: "1px solid #bfdbfe",
                        borderRadius: 999,
                        padding: "8px 13px",
                        fontWeight: 900,
                        fontFamily: "Consolas, monospace",
                      }}
                    >
                      Certificate ID: {verificationCode}
                    </div>
                  </section>
                ) : null}

                <section style={{ marginTop: 36 }}>
                  <div style={{ marginBottom: 18 }}>
                    <div
                      style={{
                        color: theme.primary,
                        fontWeight: 900,
                        fontSize: 13,
                        letterSpacing: 0.8,
                        textTransform: "uppercase",
                        marginBottom: 8,
                      }}
                    >
                      Certificate of authenticity
                    </div>
                    <h2 style={{ margin: 0, fontSize: "clamp(26px, 4vw, 34px)" }}>
                      Verification summary
                    </h2>
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                      gap: 16,
                    }}
                  >
                    <div style={infoCardStyle}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: "#dbeafe", color: "#1d4ed8", display: "grid", placeItems: "center", fontSize: 18, marginBottom: 10 }}>🛡</div>
                      <div style={infoLabelStyle}>Verification code</div>
                      <div style={{ ...infoValueStyle, fontFamily: "Consolas, monospace" }}>
                        {verificationCode}
                      </div>
                    </div>
                    <div style={infoCardStyle}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: "#ede9fe", color: "#6d28d9", display: "grid", placeItems: "center", fontSize: 18, marginBottom: 10 }}>📅</div>
                      <div style={infoLabelStyle}>Verified on</div>
                      <div style={infoValueStyle}>{formatDate(verifiedOn)}</div>
                    </div>
                    <div style={infoCardStyle}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: "#ccfbf1", color: "#0f766e", display: "grid", placeItems: "center", fontSize: 18, marginBottom: 10 }}>🏷</div>
                      <div style={infoLabelStyle}>Stamp label</div>
                      <div style={infoValueStyle}>{theme.label}</div>
                    </div>
                    <div style={infoCardStyle}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: "#dcfce7", color: "#166534", display: "grid", placeItems: "center", fontSize: 18, marginBottom: 10 }}>✓</div>
                      <div style={infoLabelStyle}>Document integrity</div>
                      <div style={{ ...infoValueStyle, color: verified ? "#166534" : status.color }}>
                        {verified ? "No alterations detected" : "Not confirmed"}
                      </div>
                    </div>
                  </div>
                </section>

                <section
                  style={{
                    marginTop: 28,
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                    gap: 18,
                  }}
                >
                  <div
                    style={{
                      background: "#eff6ff",
                      border: "1px solid #bfdbfe",
                      borderRadius: 18,
                      padding: 22,
                    }}
                  >
                    <h3 style={{ margin: "0 0 8px", color: theme.accent }}>
                      Verification statement
                    </h3>
                    <p style={{ margin: 0, color: "#475569", lineHeight: 1.7 }}>
                      This document has been cryptographically verified against the
                      issuing organization’s official electronic stamp record. No evidence
                      of tampering was detected at the time of verification.
                    </p>
                  </div>

                  <div
                    style={{
                      background: "#f8fafc",
                      border: "1px solid #dbe4f0",
                      borderRadius: 18,
                      padding: 22,
                    }}
                  >
                    <div style={{ ...infoLabelStyle, color: "#1d4ed8" }}>
                      ✔ VERIFIED ORGANIZATION
                    </div>

                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        marginBottom: 12,
                      }}
                    >
                      {theme.logo ? (
                        <img
                          src={theme.logo}
                          alt={`${theme.orgName} logo`}
                          style={{
                            width: 46,
                            height: 46,
                            objectFit: "contain",
                            borderRadius: 12,
                            background: "#ffffff",
                            border: "1px solid #dbeafe",
                            padding: 6,
                            boxSizing: "border-box",
                          }}
                        />
                      ) : (
                        <div
                          style={{
                            width: 46,
                            height: 46,
                            borderRadius: 12,
                            background: "#dbeafe",
                            color: theme.primary,
                            display: "grid",
                            placeItems: "center",
                            fontWeight: 950,
                          }}
                        >
                          ✓
                        </div>
                      )}

                      <div>
                        <div style={{ color: "#64748b", fontSize: 12, fontWeight: 900, textTransform: "uppercase", letterSpacing: 0.5 }}>
                          Issued by
                        </div>
                        <div style={{ fontSize: 20, fontWeight: 900, marginTop: 3 }}>
                          {theme.orgName}
                        </div>
                        <div style={{ color: "#64748b", fontSize: 13, marginTop: 4 }}>
                          Official Digital Stamp Authority
                        </div>
                      </div>
                    </div>
                    {theme.supportEmail ? (
                      <div style={{ color: "#475569", marginBottom: 8, overflowWrap: "anywhere" }}>
                        <strong>Primary Contact:</strong> {theme.supportEmail}
                      </div>
                    ) : null}
                    {theme.websiteUrl ? (
                      <div style={{ color: "#475569", overflowWrap: "anywhere" }}>
                        <strong>Website:</strong> {theme.websiteUrl}
                      </div>
                    ) : null}
                  </div>
                </section>

                <section
                  style={{
                    marginTop: 28,
                    background: "#ffffff",
                    border: "1px solid #dbe4f0",
                    borderRadius: 18,
                    overflow: "hidden",
                  }}
                >
                  <button
                    type="button"
                    onClick={() => setTechnicalOpen((current) => !current)}
                    style={{
                      width: "100%",
                      border: 0,
                      background: technicalOpen ? "#f8fafc" : "#ffffff",
                      padding: "18px 20px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 16,
                      cursor: "pointer",
                      color: "#0f172a",
                      fontWeight: 900,
                      fontSize: 16,
                      textAlign: "left",
                    }}
                  >
                    Verification information
                    <span style={{ color: theme.primary, fontSize: 22 }}>
                      {technicalOpen ? "−" : "+"}
                    </span>
                  </button>

                  {technicalOpen ? (
                    <div style={{ borderTop: "1px solid #e2e8f0", padding: 20, display: "grid", gap: 16 }}>
                      <TechnicalRow label="Verification Code" value={verificationCode} />
                      <TechnicalRow label="Document ID" value={details?.document_id || payload?.doc_id || "—"} />
                      <TechnicalRow label="Stamp ID" value={details?.stamp_id || payload?.stamp_id || "—"} />
                      <TechnicalRow label="Verification Timestamp" value={formatDate(verifiedOn)} />
                      <TechnicalRow label="Hash Algorithm" value="SHA-256" />
                      <TechnicalRow label="Verification Server" value="eStamp Pro Cloud" />
                      <TechnicalRow label="Verification URL" value={payload?.verify_url || window.location.href} />
                    </div>
                  ) : null}
                </section>

                <section style={{ marginTop: 34, display: "flex", gap: 14, flexWrap: "wrap" }}>
                  {certificateUrl ? (
                    <a
                      href={certificateUrl}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        ...primaryButton,
                        minHeight: 50,
                        padding: "0 22px",
                        fontSize: 15,
                        boxShadow: "0 10px 24px rgba(29,78,216,0.18)",
                      }}
                    >
                      ⬇ Download Certificate
                    </a>
                  ) : null}
                  {emailTemplateUrl ? (
                    <a
                      href={emailTemplateUrl}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        ...secondaryButton,
                        minHeight: 50,
                        padding: "0 22px",
                        fontSize: 15,
                      }}
                    >
                      ✉ View Verification Email
                    </a>
                  ) : null}
                </section>
              </>
            )}
          </div>

          <div
            aria-hidden="true"
            style={{
              position: "absolute",
              right: 28,
              bottom: 96,
              textAlign: "right",
              color: "#1d4ed8",
              opacity: 0.035,
              fontWeight: 950,
              fontSize: 34,
              lineHeight: 1.05,
              pointerEvents: "none",
              userSelect: "none",
            }}
          >
            Verified by
            <br />
            eStamp Pro
          </div>

          <section
            style={{
              borderTop: "1px solid #e2e8f0",
              background: "#ffffff",
              padding: "22px 28px",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 13,
                fontWeight: 950,
                color: "#0f172a",
                textTransform: "uppercase",
                letterSpacing: 0.9,
                marginBottom: 12,
              }}
            >
              Trusted by eStamp Pro
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              {["QR Verified", "Digitally Certified", "Audit Trail Protected", "Cryptographically Verified"].map((item) => (
                <span
                  key={item}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    background: "#eff6ff",
                    border: "1px solid #bfdbfe",
                    color: "#1d4ed8",
                    borderRadius: 999,
                    padding: "8px 12px",
                    fontSize: 12,
                    fontWeight: 900,
                  }}
                >
                  ✓ {item}
                </span>
              ))}
            </div>
          </section>

          <footer
            style={{
              borderTop: "1px solid #e2e8f0",
              background: "#f8fafc",
              padding: "24px 28px",
              color: "#64748b",
              fontSize: 13,
              textAlign: "center",
            }}
          >
            <strong style={{ color: "#334155", fontSize: 14 }}>
              Verified by eStamp Pro
            </strong>
            <div style={{ marginTop: 6 }}>
              Secure Digital Verification Platform
            </div>
            <div style={{ marginTop: 4, fontSize: 12 }}>
              QR Verification • Digital Certificate • Cryptographic Integrity • Audit Trail Protection
            </div>
            <div
              style={{
                marginTop: 12,
                display: "flex",
                justifyContent: "center",
                gap: 14,
                flexWrap: "wrap",
              }}
            >
              <a href="https://estamppro.com/privacy" style={{ color: "#475569" }}>
                Privacy
              </a>
              <a href="https://estamppro.com/terms" style={{ color: "#475569" }}>
                Terms
              </a>
              <a href="https://estamppro.com/contact" style={{ color: "#475569" }}>
                Support
              </a>
            </div>
            <div style={{ marginTop: 10, fontSize: 12 }}>
              © {new Date().getFullYear()} eStamp Pro
            </div>
          </footer>
        </section>
      </div>
    </main>
  );
}

function TechnicalRow({ label, value }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(150px, 190px) minmax(0, 1fr)",
        gap: 16,
        alignItems: "start",
      }}
    >
      <div style={{ fontWeight: 850, color: "#334155" }}>{label}</div>
      <div
        style={{
          color: "#111827",
          fontFamily: "Consolas, monospace",
          fontSize: 14,
          lineHeight: 1.5,
          overflowWrap: "anywhere",
          wordBreak: "break-word",
        }}
      >
        {String(value || "—")}
      </div>
    </div>
  );
}