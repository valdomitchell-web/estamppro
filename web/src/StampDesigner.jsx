import React, { useEffect, useRef, useState } from "react";
import { api } from "./api";

export default function StampDesigner({ onSaved, canCustomize = false, currentPlan = "free", onUpgrade, branding = {} }) {
  const canvasRef = useRef(null);

  const [stampName, setStampName] = useState(branding?.stamp_label || "Official Company Stamp");
  const [password, setPassword] = useState("");
  const [shape, setShape] = useState("circle");

  const [topText, setTopText] = useState("APPROVED");
  const [centerText, setCenterText] = useState("eStamp Pro");
  const [bottomText, setBottomText] = useState("OFFICIAL SEAL");

  const [borderColor, setBorderColor] = useState(branding?.primary_color || "#b91c1c");
  const [textColor, setTextColor] = useState(branding?.accent_color || branding?.primary_color || "#991b1b");
  const [borderWidth, setBorderWidth] = useState(6);
  const [fontSize, setFontSize] = useState(28);
  const [padding, setPadding] = useState(24);

  const [showQrBox, setShowQrBox] = useState(true);
  const [busy, setBusy] = useState(false);

  const canvasWidth = 500;
  const canvasHeight = 500;

  const drawStamp = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "transparent";
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;

    ctx.save();
    ctx.strokeStyle = borderColor;
    ctx.fillStyle = textColor;
    ctx.lineWidth = borderWidth;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    if (shape === "circle") {
      const radius = Math.min(w, h) / 2 - padding;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, radius - 16, 0, Math.PI * 2);
      ctx.lineWidth = Math.max(2, borderWidth / 2);
      ctx.stroke();

      drawArcText(ctx, topText, cx, cy, radius - 28, -Math.PI * 0.78, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor);
      drawArcText(ctx, bottomText, cx, cy, radius - 28, Math.PI * 0.22, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor, true);

      ctx.font = `bold ${fontSize}px Arial`;
      ctx.fillText(centerText, cx, cy);

      if (showQrBox) {
        ctx.strokeStyle = borderColor;
        ctx.lineWidth = 2;
        const qrSize = 70;
        ctx.strokeRect(cx - qrSize / 2, cy + 40, qrSize, qrSize);
        ctx.font = `12px Arial`;
        ctx.fillText("QR", cx, cy + 75);
      }
    } else {
      const rectX = padding;
      const rectY = padding + 20;
      const rectW = w - padding * 2;
      const rectH = h - padding * 2 - 40;

      ctx.lineWidth = borderWidth;
      roundRect(ctx, rectX, rectY, rectW, rectH, 18);
      ctx.stroke();

      ctx.lineWidth = Math.max(2, borderWidth / 2);
      roundRect(ctx, rectX + 12, rectY + 12, rectW - 24, rectH - 24, 14);
      ctx.stroke();

      ctx.font = `bold ${Math.max(20, fontSize * 0.72)}px Arial`;
      ctx.fillText(topText, cx, rectY + 50);

      ctx.font = `bold ${fontSize}px Arial`;
      ctx.fillText(centerText, cx, cy - 10);

      ctx.font = `bold ${Math.max(18, fontSize * 0.65)}px Arial`;
      ctx.fillText(bottomText, cx, rectY + rectH - 40);

      if (showQrBox) {
        ctx.lineWidth = 2;
        const qrSize = 70;
        ctx.strokeRect(rectX + rectW - qrSize - 24, rectY + 24, qrSize, qrSize);
        ctx.font = `12px Arial`;
        ctx.fillText("QR", rectX + rectW - qrSize / 2 - 24, rectY + 24 + qrSize / 2);
      }
    }

    ctx.restore();
  };


  useEffect(() => {
    if (!branding) return;
    if (branding?.stamp_label) setStampName((prev) => prev === "Official Company Stamp" ? branding.stamp_label : prev);
    if (branding?.primary_color) setBorderColor((prev) => prev === "#b91c1c" ? branding.primary_color : prev);
    if (branding?.accent_color || branding?.primary_color) {
      const next = branding?.accent_color || branding?.primary_color;
      setTextColor((prev) => prev === "#991b1b" ? next : prev);
    }
  }, [branding]);

  useEffect(() => {
    drawStamp();
  }, [
    shape,
    topText,
    centerText,
    bottomText,
    borderColor,
    textColor,
    borderWidth,
    fontSize,
    padding,
    showQrBox,
  ]);

  const exportPng = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const link = document.createElement("a");
    link.download = `${stampName || "stamp"}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
  };

  const saveStamp = async () => {
    if (!canCustomize) {
      alert("Custom stamp designer is available on Pro and Business.");
      return;
    }

    if (!password.trim()) {
      alert("Enter a stamp password.");
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    try {
      setBusy(true);
      const blob = await new Promise((resolve) =>
        canvas.toBlob(resolve, "image/png")
      );

      if (!blob) throw new Error("Could not create PNG");

      const form = new FormData();
      form.append("image", blob, `${stampName || "stamp"}.png`);
      form.append("name", stampName || "Stamp");
      form.append("password", password);
      form.append("width", String(canvas.width));
      form.append("height", String(canvas.height));
      form.append("designType", "custom");
      form.append("shape", shape);
      form.append("topText", topText);
      form.append("centerText", centerText);
      form.append("bottomText", bottomText);
      form.append("borderColor", borderColor);
      form.append("textColor", textColor);
      form.append("borderWidth", String(borderWidth));
      form.append("fontSize", String(fontSize));
      form.append("padding", String(padding));
      form.append("showQrBox", String(showQrBox));

      const res = await api.post("/stamps", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      alert("Stamp saved successfully.");

      if (typeof onSaved === "function") {
        onSaved(res.data?.stamp || null);
      }
    } catch (e) {
      console.error(e);
      alert(
        e?.response?.data?.detail ||
          e?.response?.data?.error ||
          e.message ||
          "Failed to save stamp"
      );
    } finally {
      setBusy(false);
    }
  };

  const useCircularPreset = () => {
    setShape("circle");
    setTopText("APPROVED");
    setCenterText("eStamp Pro");
    setBottomText("OFFICIAL SEAL");
    setBorderColor(branding?.primary_color || "#b91c1c");
    setTextColor(branding?.accent_color || branding?.primary_color || "#991b1b");
    setBorderWidth(6);
    setFontSize(28);
    setPadding(24);
    setShowQrBox(true);
  };

  const useRectPreset = () => {
    setShape("rect");
    setTopText("RECEIVED");
    setCenterText("BUSINESS STAMP");
    setBottomText("AUTHORIZED");
    setBorderColor(branding?.primary_color || "#1d4ed8");
    setTextColor(branding?.accent_color || branding?.primary_color || "#1e3a8a");
    setBorderWidth(6);
    setFontSize(26);
    setPadding(24);
    setShowQrBox(true);
  };

  return (
    <div
      style={{
        border: "1px solid #dbe4f0",
        borderRadius: 14,
        padding: 18,
        background: "#ffffff",
        boxShadow: "0 6px 20px rgba(15, 23, 42, 0.05)",
      }}
    >
      {!canCustomize && (
        <div
          style={{
            marginBottom: 16,
            padding: 14,
            borderRadius: 12,
            background: "#fffbeb",
            border: "1px solid #fde68a",
            color: "#92400e",
          }}
        >
          <div style={{ fontWeight: 700, marginBottom: 6 }}>
            Custom stamp designer is locked on the {currentPlan} plan.
          </div>
          <div style={{ marginBottom: 10 }}>
            Upgrade to Pro or Business to create branded circular and rectangular stamp designs.
          </div>
          <button
            type="button"
            onClick={() => typeof onUpgrade === "function" && onUpgrade()}
            style={toolButtonStyle}
          >
            Upgrade to unlock
          </button>
        </div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20, opacity: canCustomize ? 1 : 0.7 }}>
        <div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
            <button type="button" onClick={useCircularPreset} style={toolButtonStyle} disabled={!canCustomize}>
              Circular Seal
            </button>
            <button type="button" onClick={useRectPreset} style={toolButtonStyle} disabled={!canCustomize}>
              Official Rectangle
            </button>
            <button type="button" onClick={exportPng} style={toolButtonStyle}>
              Download PNG
            </button>
            <button
              type="button"
              onClick={saveStamp}
              disabled={busy || !canCustomize}
              style={primaryButtonStyle}
            >
              {busy ? "Saving..." : "Save as Stamp"}
            </button>
          </div>

          <div
            style={{
              width: canvasWidth,
              maxWidth: "100%",
              border: "1px dashed #94a3b8",
              borderRadius: 10,
              overflow: "hidden",
              background: "transparent",
            }}
          >
            <canvas
              ref={canvasRef}
              width={canvasWidth}
              height={canvasHeight}
              style={{
                display: "block",
                width: "100%",
                height: "auto",
                background: "transparent",
              }}
            />
          </div>
        </div>

        <div>
          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Stamp Name</label>
            <input
              style={inputStyle}
              value={stampName}
              onChange={(e) => setStampName(e.target.value)}
            />
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Stamp Password</label>
            <input
              type="password"
              style={inputStyle}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Shape</label>
            <select
              style={inputStyle}
              value={shape}
              onChange={(e) => setShape(e.target.value)}
            >
              <option value="circle">Circle</option>
              <option value="rect">Rectangle</option>
            </select>
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Top Text</label>
            <input
              style={inputStyle}
              value={topText}
              onChange={(e) => setTopText(e.target.value)}
            />
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Center Text</label>
            <input
              style={inputStyle}
              value={centerText}
              onChange={(e) => setCenterText(e.target.value)}
            />
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Bottom Text</label>
            <input
              style={inputStyle}
              value={bottomText}
              onChange={(e) => setBottomText(e.target.value)}
            />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={fieldBlockStyle}>
              <label style={labelStyle}>Border Color</label>
              <input
                type="color"
                style={colorInputStyle}
                value={borderColor}
                onChange={(e) => setBorderColor(e.target.value)}
              />
            </div>

            <div style={fieldBlockStyle}>
              <label style={labelStyle}>Text Color</label>
              <input
                type="color"
                style={colorInputStyle}
                value={textColor}
                onChange={(e) => setTextColor(e.target.value)}
              />
            </div>
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Border Thickness</label>
            <input
              type="range"
              min="2"
              max="14"
              value={borderWidth}
              onChange={(e) => setBorderWidth(Number(e.target.value))}
              style={{ width: "100%" }}
            />
            <div>{borderWidth}px</div>
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Font Size</label>
            <input
              type="range"
              min="16"
              max="42"
              value={fontSize}
              onChange={(e) => setFontSize(Number(e.target.value))}
              style={{ width: "100%" }}
            />
            <div>{fontSize}px</div>
          </div>

          <div style={fieldBlockStyle}>
            <label style={labelStyle}>Padding</label>
            <input
              type="range"
              min="10"
              max="60"
              value={padding}
              onChange={(e) => setPadding(Number(e.target.value))}
              style={{ width: "100%" }}
            />
            <div>{padding}px</div>
          </div>

          <div style={fieldBlockStyle}>
            <label style={{ ...labelStyle, display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={showQrBox}
                onChange={(e) => setShowQrBox(e.target.checked)}
              />
              Show QR placeholder
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}

function drawArcText(
  ctx,
  text,
  cx,
  cy,
  radius,
  startAngle,
  totalAngle,
  fontSize,
  color,
  reverse = false
) {
  if (!text) return;

  ctx.save();
  ctx.fillStyle = color;
  ctx.font = `bold ${fontSize}px Arial`;

  const chars = text.split("");
  const step = totalAngle / Math.max(chars.length - 1, 1);

  chars.forEach((char, i) => {
    const angle = reverse
      ? startAngle + (chars.length - 1 - i) * step
      : startAngle + i * step;

    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);

    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(angle + (reverse ? Math.PI / 2 : Math.PI / 2));
    ctx.fillText(char, 0, 0);
    ctx.restore();
  });

  ctx.restore();
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

const fieldBlockStyle = {
  marginBottom: 12,
};

const labelStyle = {
  display: "block",
  marginBottom: 6,
  fontWeight: 600,
  color: "#374151",
};

const inputStyle = {
  width: "100%",
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid #cbd5e1",
  fontSize: 15,
  background: "#fff",
  color: "#0f172a",
  boxSizing: "border-box",
};

const colorInputStyle = {
  width: "100%",
  height: 42,
  borderRadius: 10,
  border: "1px solid #cbd5e1",
  background: "#fff",
};

const toolButtonStyle = {
  background: "#eff6ff",
  color: "#1d4ed8",
  border: "1px solid #bfdbfe",
  borderRadius: 10,
  padding: "9px 12px",
  cursor: "pointer",
  fontWeight: 700,
};

const primaryButtonStyle = {
  background: "#1d4ed8",
  color: "#fff",
  border: "none",
  borderRadius: 10,
  padding: "9px 14px",
  cursor: "pointer",
  fontWeight: 700,
  boxShadow: "0 2px 8px rgba(29, 78, 216, 0.18)",
};