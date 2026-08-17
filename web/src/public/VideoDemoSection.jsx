import React from "react";

export default function VideoDemoSection() {
  return (
    <section
      id="demo"
      style={{
        padding: "88px 24px",
        background: "linear-gradient(180deg, #ffffff 0%, #f8fbff 100%)",
      }}
    >
      <div style={{ maxWidth: 1120, margin: "0 auto" }}>
        <div
          style={{
            maxWidth: 760,
            margin: "0 auto 36px",
            textAlign: "center",
          }}
        >
          <div
            style={{
              color: "#1d4ed8",
              fontWeight: 900,
              marginBottom: 10,
              letterSpacing: 0.6,
            }}
          >
            SEE ESTAMP PRO IN ACTION
          </div>

          <h2
            style={{
              margin: "0 0 16px",
              color: "#0f172a",
              fontSize: "clamp(32px, 5vw, 48px)",
              lineHeight: 1.08,
              letterSpacing: "-1px",
            }}
          >
            From PDF to professionally stamped and verifiable
          </h2>

          <p
            style={{
              margin: 0,
              color: "#64748b",
              fontSize: 17,
              lineHeight: 1.75,
            }}
          >
            Create professional electronic stamps, apply them to PDFs, add
            authorized signatures, and give recipients a simple way to verify
            document authenticity and integrity.
          </p>
        </div>

        <div
          style={{
            maxWidth: 980,
            margin: "0 auto",
            padding: 12,
            borderRadius: 24,
            background: "#0f172a",
            boxShadow: "0 24px 60px rgba(15,23,42,0.16)",
          }}
        >
          <video
            controls
            preload="metadata"
            playsInline
            poster="/images/estamp-pro-video-poster.jpg"
            style={{
              display: "block",
              width: "100%",
              height: "auto",
              borderRadius: 16,
              background: "#000",
            }}
          >
            <source
              src="/videos/eStamp_Pro_Launch_Final_Captioned_Small_SingleVoice.mp4"
              type="video/mp4"
            />
            Your browser does not support HTML video.
          </video>
        </div>

        <div
          style={{
            marginTop: 34,
            textAlign: "center",
          }}
        >
          <h3
            style={{
              margin: "0 0 10px",
              color: "#0f172a",
              fontSize: 26,
            }}
          >
            Ready to build trust into your documents?
          </h3>

          <p
            style={{
              margin: "0 auto 22px",
              color: "#64748b",
              fontSize: 16,
              lineHeight: 1.7,
            }}
          >
            Start free today. No credit card required.
          </p>

          <div
            style={{
              display: "flex",
              justifyContent: "center",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <a
              href="https://app.estamppro.com/?auth=register&fresh=1"
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                background: "#1d4ed8",
                color: "#ffffff",
                textDecoration: "none",
                padding: "14px 20px",
                borderRadius: 12,
                fontWeight: 900,
                boxShadow: "0 12px 28px rgba(29,78,216,0.22)",
              }}
            >
              Start Free Today
            </a>

            <a
              href="/pricing"
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                background: "#ffffff",
                color: "#1d4ed8",
                textDecoration: "none",
                padding: "14px 20px",
                borderRadius: 12,
                fontWeight: 900,
                border: "1px solid #bfdbfe",
              }}
            >
              View Pricing
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}