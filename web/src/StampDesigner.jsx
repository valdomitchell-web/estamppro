import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";

export default function StampDesigner({
  onSaved,
  canCustomize = false,
  canUploadActual = false,
  canUsePresetLogo = false,
  currentPlan = "free",
  onUpgrade,
  branding = {},
}) {
  const canvasRef = useRef(null);
  const logoImgRef = useRef(null);

  const [mode, setMode] = useState(canCustomize ? "preset" : "upload");
  const [stampName, setStampName] = useState(branding?.stamp_label || "Official Company Stamp");
  const [password, setPassword] = useState("");
  const [shape, setShape] = useState("circle");
  const [presetTemplate, setPresetTemplate] = useState("classicSeal");

  const [topText, setTopText] = useState("APPROVED");
  const [centerText, setCenterText] = useState("eStamp Pro");
  const [bottomText, setBottomText] = useState("OFFICIAL SEAL");
  const [corporateText, setCorporateText] = useState("CORPORATE");
  const [establishedYear, setEstablishedYear] = useState("2025");

  const [borderColor, setBorderColor] = useState(branding?.primary_color || "#b91c1c");
  const [textColor, setTextColor] = useState(branding?.accent_color || branding?.primary_color || "#991b1b");
  const [borderWidth, setBorderWidth] = useState(6);
  const [fontSize, setFontSize] = useState(28);
  const [padding, setPadding] = useState(24);
  const [showQrBox, setShowQrBox] = useState(false);

  const [uploadFile, setUploadFile] = useState(null);
  const [uploadPreview, setUploadPreview] = useState("");
  //const [actualStampScale, setActualStampScale] = useState(1);
//const [actualStampOpacity, setActualStampOpacity] = useState(1);

const [logoReady, setLogoReady] = useState(false);
  const [logoFile, setLogoFile] = useState(null);
  const [logoPreview, setLogoPreview] = useState("");
  //const [logoPlacement, setLogoPlacement] = useState("center");
  const [busy, setBusy] = useState(false);
const [logoX, setLogoX] = useState(205);
const [logoY, setLogoY] = useState(145);
const [logoW, setLogoW] = useState(42);
const [logoH, setLogoH] = useState(42);


  const canvasWidth = 500;
  const canvasHeight = 500;

  useEffect(() => {
    if (canCustomize) {
      setMode((prev) => (prev === "upload" && !canUploadActual ? "preset" : prev));
    } else if (canUploadActual) {
      setMode("upload");
    }
  }, [canCustomize, canUploadActual]);

  useEffect(() => {
    if (!branding) return;
    if (branding?.stamp_label) {
      setStampName((prev) => (prev === "Official Company Stamp" ? branding.stamp_label : prev));
    }
    if (branding?.primary_color) {
      setBorderColor((prev) => (prev === "#b91c1c" ? branding.primary_color : prev));
    }
    if (branding?.accent_color || branding?.primary_color) {
      const next = branding?.accent_color || branding?.primary_color;
      setTextColor((prev) => (prev === "#991b1b" ? next : prev));
    }
  }, [branding]);

  useEffect(() => {
    if (!uploadFile) {
      setUploadPreview("");
      return;
    }
    const url = URL.createObjectURL(uploadFile);
    setUploadPreview(url);
    return () => URL.revokeObjectURL(url);
  }, [uploadFile]);

  useEffect(() => {
  if (!logoFile) {
    setLogoPreview("");
    logoImgRef.current = null;
    setLogoReady(false);
    return;
  }

  const url = URL.createObjectURL(logoFile);
  setLogoPreview(url);
  setLogoReady(false);

  const img = new Image();

  img.onload = () => {
    logoImgRef.current = img;
    setLogoReady(true);
  };

  img.onerror = () => {
    logoImgRef.current = null;
    setLogoReady(false);
  };

  img.src = url;

  return () => {
    URL.revokeObjectURL(url);
  };
}, [logoFile]);

  const hasLogoOverlay = useMemo(
  () => canUsePresetLogo && !!logoPreview && logoReady && !!logoImgRef.current,
  [canUsePresetLogo, logoPreview, logoReady]
);

  useEffect(() => {
    drawStamp();
  }, [
    mode,
    shape,
    presetTemplate,
    topText,
    centerText,
    bottomText,
    corporateText,
    establishedYear,
    borderColor,
    textColor,
    borderWidth,
    fontSize,
    padding,
    //showQrBox,
    //logoPlacement,
    logoPreview,
    logoReady,
    logoX,
logoY,
logoW,
logoH,
  ]);

  const drawLogoOverlay = (ctx, canvas, logoImg) => {
  if (!logoImg || !canUsePresetLogo) return;

  const aspect = logoImg.width / Math.max(logoImg.height, 1);

  let drawW = Number(logoW) || 90;
  let drawH = Number(logoH) || 90;

  if (!logoH) {
    drawH = drawW / aspect;
  }

  ctx.save();
  ctx.globalAlpha = 0.95;
  ctx.drawImage(
    logoImg,
    Number(logoX) || 0,
    Number(logoY) || 0,
    drawW,
    drawH
  );
  ctx.restore();
};

  // Draw glyphs on a measured arc. Bottom glyphs remain upright and read
  // left-to-right instead of being inverted by the lower semicircle.
  function drawArcText(ctx, text, cx, cy, radius, startAngle, arcAngle, size, color, bottom = false) {
    const value = String(text || "").trim();
    if (!value) return;
    ctx.save();
    ctx.fillStyle = color;
    ctx.font = `bold ${size}px Arial`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    const chars = Array.from(value);
    const widths = chars.map((char) => ctx.measureText(char).width);
    const naturalSpan = widths.reduce((sum, width) => sum + width, 0) / radius;
    const maxSpan = Math.abs(arcAngle);
    const scale = naturalSpan > maxSpan ? maxSpan / naturalSpan : 1;
    const span = naturalSpan * scale;
    let cursor = -span / 2;
    const midpoint = startAngle + arcAngle / 2;
    for (let i = 0; i < chars.length; i++) {
      const widthAngle = (widths[i] / radius) * scale;
      const offset = cursor + widthAngle / 2;
      const angle = midpoint + (bottom ? -offset : offset);
      ctx.save();
      ctx.translate(cx + Math.cos(angle) * radius, cy + Math.sin(angle) * radius);
      ctx.rotate(angle + (bottom ? -Math.PI / 2 : Math.PI / 2));
      ctx.scale(scale, 1);
      ctx.fillText(chars[i], 0, 0);
      ctx.restore();
      cursor += widthAngle;
    }
    ctx.restore();
  }

  function roundRect(ctx, x, y, width, height, radius) {
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + width - radius, y);
    ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
    ctx.lineTo(x + width, y + height - radius);
    ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
    ctx.lineTo(x + radius, y + height);
    ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
  }

  function drawLogo(ctx, bounds) {
    const img = logoImgRef.current;
    if (!img || !hasLogoOverlay) return;

    const aspect = img.width / Math.max(1, img.height);
    let drawW = bounds.w;
    let drawH = drawW / aspect;
    if (drawH > bounds.h) {
      drawH = bounds.h;
      drawW = drawH * aspect;
    }

    const x = bounds.x + (bounds.w - drawW) / 2;
    const y = bounds.y + (bounds.h - drawH) / 2;
    ctx.drawImage(img, x, y, drawW, drawH);
  }

  const isCorporateStyle = presetTemplate === "corporateSeal" || presetTemplate === "modernCorporateSeal";

  const drawStamp = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;

    const logoImg = logoImgRef.current;
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

      if (presetTemplate === "doubleRing") {
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, radius - 65, 0, Math.PI * 2);
        ctx.lineWidth = Math.max(2, borderWidth / 2);
        ctx.stroke();
        ctx.restore();
      }

      if (isCorporateStyle) {
        const modern = presetTemplate === "modernCorporateSeal";
        ctx.save();
        ctx.strokeStyle = borderColor;
        if (modern) {
          // A restrained geometric seal with a spacious central field.
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(cx, cy, radius - 80, 0, Math.PI * 2);
          ctx.stroke();
          // Small side markers separate the upper and lower text bands.
          ctx.fillStyle = borderColor;
          for (const x of [cx - (radius - 47), cx + (radius - 47)]) {
            ctx.beginPath();
            ctx.arc(x, cy, 3, 0, Math.PI * 2);
            ctx.fill();
          }
        } else {
          // Fine radial engraving and a light dotted inner circle.
          ctx.lineWidth = 1.2;
          for (let i = 0; i < 180; i++) {
            const angle = (i / 180) * Math.PI * 2;
            const r1 = radius - 4;
            const r2 = radius - 14;
            ctx.beginPath();
            ctx.moveTo(cx + Math.cos(angle) * r1, cy + Math.sin(angle) * r1);
            ctx.lineTo(cx + Math.cos(angle) * r2, cy + Math.sin(angle) * r2);
            ctx.stroke();
          }
          ctx.beginPath();
          ctx.setLineDash([2, 7]);
          ctx.arc(cx, cy, radius - 92, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.restore();
        drawArcText(ctx, topText, cx, cy, radius - 46, -Math.PI * 0.85, Math.PI * 0.7, Math.max(18, fontSize * 0.9), textColor);
        drawArcText(ctx, bottomText, cx, cy, radius - 46, Math.PI * 0.15, Math.PI * 0.7, Math.max(18, fontSize * 0.85), textColor, true);
        drawArcText(ctx, corporateText, cx, cy, modern ? radius - 108 : radius - 122, -Math.PI * 0.83, Math.PI * 0.66, Math.max(16, fontSize * 0.75), textColor);
        ctx.font = `${modern ? "500" : "bold"} ${Math.max(17, fontSize * 0.75)}px ${modern ? "Arial, sans-serif" : "Georgia, serif"}`;
        ctx.fillText(`EST. ${establishedYear}`, cx, cy + (modern ? 80 : 92));
        ctx.font = `${modern ? "600" : "bold"} ${Math.max(42, fontSize * (modern ? 1.7 : 2.0))}px ${modern ? "Arial, sans-serif" : "Georgia, serif"}`;
        ctx.fillText(centerText, cx, cy + 5, radius * 1.1);
      } else {
        drawArcText(ctx, topText, cx, cy, radius - 28, -Math.PI * 0.78, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor);
        drawArcText(ctx, bottomText, cx, cy, radius - 28, Math.PI * 0.22, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor, true);
      }

      if (hasLogoOverlay && logoImg) {
        drawLogoOverlay(ctx, canvas, logoImg);
        if (!isCorporateStyle) {
          ctx.font = `bold ${Math.max(18, fontSize * 0.72)}px Arial`;
          ctx.fillText(centerText, cx, cy + 68);
        }
      } else if (!isCorporateStyle) {
        ctx.font = `bold ${fontSize}px Arial`;
        ctx.fillText(centerText, cx, cy);
      }

      //if (showQrBox) {
        //ctx.strokeStyle = borderColor;
        //ctx.lineWidth = 2;
        //const qrSize = 55;
        //ctx.strokeRect(cx - qrSize / 2, cy + 82, qrSize, qrSize);
        //ctx.font = `10px Arial`;
        //ctx.fillText("QR", cx, cy + 106);
      //}
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

if (presetTemplate === "doubleRing") {
  ctx.lineWidth = Math.max(2, borderWidth / 2);
  roundRect(ctx, rectX + 24, rectY + 24, rectW - 48, rectH - 48, 10);
  ctx.stroke();
}

if (presetTemplate === "officeBox") {
  ctx.beginPath();
  ctx.moveTo(rectX + 28, rectY + 98);
  ctx.lineTo(rectX + rectW - 28, rectY + 98);
  ctx.stroke();
}

      ctx.font = `bold ${Math.max(20, fontSize * 0.72)}px Arial`;
      ctx.fillText(topText, cx, rectY + 50);

      if (hasLogoOverlay && logoImg) {
  drawLogoOverlay(ctx, canvas, logoImg);
        ctx.textAlign = "left";
        ctx.font = `bold ${Math.max(20, fontSize * 0.9)}px Arial`;
        ctx.fillText(centerText, rectX + 150, cy - 6);
        ctx.textAlign = "center";
      } else {
        ctx.font = `bold ${fontSize}px Arial`;
        ctx.fillText(centerText, cx, cy - 10);
      }

      ctx.font = `bold ${Math.max(18, fontSize * 0.65)}px Arial`;
      ctx.fillText(bottomText, cx, rectY + rectH - 40);

      //if (showQrBox) {
        //ctx.lineWidth = 2;
       // const qrSize = 55;
       // ctx.strokeRect(rectX + rectW - qrSize - 24, rectY + 24, qrSize, qrSize);
        //ctx.font = `12px Arial`;
       // ctx.fillText("QR", rectX + rectW - qrSize / 2 - 24, rectY + 24 + qrSize / 2);
      //}
    }

    ctx.restore();
  };

  const exportPng = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const link = document.createElement("a");
    link.download = `${stampName || "stamp"}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
  };

  const savePresetStamp = async () => {
    if (!canCustomize) {
      alert("Preset stamp design is available on Pro and Business.");
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
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
      if (!blob) throw new Error("Could not create PNG");

      const form = new FormData();
      form.append("image", blob, `${stampName || "stamp"}.png`);
      form.append("name", stampName || "Stamp");
      form.append("password", password);
      form.append("width", String(canvas.width));
      form.append("height", String(canvas.height));
      form.append("designType", hasLogoOverlay ? "preset_logo" : "custom");
      form.append("shape", shape);
      form.append("topText", topText);
      form.append("centerText", centerText);
      form.append("bottomText", bottomText);
      form.append("corporateText", corporateText);
      form.append("establishedYear", establishedYear);
      form.append("borderColor", borderColor);
      form.append("textColor", textColor);
      form.append("borderWidth", String(borderWidth));
      form.append("fontSize", String(fontSize));
      form.append("padding", String(padding));
     // form.append("showQrBox", String(showQrBox));
      form.append("presetTemplate", presetTemplate);
      form.append("logoIncluded", String(hasLogoOverlay));
      //form.append("logoPlacement", logoPlacement);

      const res = await api.post("/stamps", form, {
  headers: { "Content-Type": "multipart/form-data" },
});

alert(
  hasLogoOverlay
    ? "Branded preset stamp saved. Select the new stamp before applying it."
    : "Custom stamp saved successfully. Select the new stamp before applying it."
);

if (typeof onSaved === "function") {
  onSaved(res.data?.stamp || null);
}

// 👇 ADD THIS HERE
if (typeof window !== "undefined") {
  window.dispatchEvent(new CustomEvent("stamp-saved"));
}

    } catch (e) {
      console.error(e);
      alert(e?.response?.data?.detail || e?.response?.data?.error || e.message || "Failed to save stamp");
    } finally {
      setBusy(false);
    }
  };

  const saveUploadedStamp = async () => {
    if (!canUploadActual) {
      alert(
  hasLogoOverlay
    ? "Branded preset stamp saved. Select the new stamp before applying it."
    : "Custom stamp saved successfully. Select the new stamp before applying it."
);
      return;
    }
    if (!uploadFile) {
      alert("Choose a PNG file for your stamp.");
      return;
    }
    if (!password.trim()) {
      alert("Enter a stamp password.");
      return;
    }

    try {
      setBusy(true);
      const form = new FormData();
      form.append("image", uploadFile);
      form.append("name", stampName || uploadFile.name.replace(/\.[^.]+$/, "") || "Uploaded Stamp");
      form.append("password", password);
      form.append("designType", "uploaded");
      const res = await api.post("/stamps", form, { headers: { "Content-Type": "multipart/form-data" } });
      alert("Actual stamp uploaded successfully.");
      if (typeof onSaved === "function") onSaved(res.data?.stamp || null);
    } catch (e) {
      console.error(e);
      alert(e?.response?.data?.detail || e?.response?.data?.error || e.message || "Failed to upload stamp");
    } finally {
      setBusy(false);
    }
  };

  const useCircularPreset = () => {
    setShape("circle");
    setPresetTemplate("classicSeal");
    setTopText("APPROVED");
    setCenterText("eStamp Pro");
    setBottomText("OFFICIAL SEAL");
    setBorderColor(branding?.primary_color || "#b91c1c");
    setTextColor(branding?.accent_color || branding?.primary_color || "#991b1b");
    setBorderWidth(6);
    setFontSize(28);
    setPadding(24);
   // setShowQrBox(false);
  };

  const useCorporatePreset = () => {
    setShape("circle");
    setPresetTemplate("corporateSeal");
    setTopText("COMPANY NAME");
    setCenterText("SEAL");
    setBottomText("STATE");
    setCorporateText("CORPORATE");
    setEstablishedYear("2025");
    setBorderColor("#171717");
    setTextColor("#171717");
    setBorderWidth(5);
    setFontSize(28);
    setPadding(24);
  };

  const useModernCorporatePreset = () => {
    setShape("circle");
    setPresetTemplate("modernCorporateSeal");
    setTopText("COMPANY NAME");
    setCenterText("SEAL");
    setBottomText("REGISTERED");
    setCorporateText("CORPORATE");
    setEstablishedYear("2025");
    setBorderColor("#243447");
    setTextColor("#243447");
    setBorderWidth(3);
    setFontSize(27);
    setPadding(24);
  };

  const useRectPreset = () => {
    setShape("rect");
    setPresetTemplate("officeBox");
    setTopText("RECEIVED");
    setCenterText("BUSINESS STAMP");
    setBottomText("AUTHORIZED");
    setBorderColor(branding?.primary_color || "#1d4ed8");
    setTextColor(branding?.accent_color || branding?.primary_color || "#1e3a8a");
    setBorderWidth(6);
    setFontSize(26);
    setPadding(24);
    //setShowQrBox(false);
  };

  return (
    <div style={{ border: "1px solid #dbe4f0", borderRadius: 14, padding: 18, background: "#ffffff", boxShadow: "0 6px 20px rgba(15, 23, 42, 0.05)" }}>
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        <button
          type="button"
          onClick={() => setMode("preset")}
          style={{
            padding: "10px 14px",
            borderRadius: 999,
            border: mode === "preset" ? "1px solid #1d4ed8" : "1px solid #cbd5e1",
            background: mode === "preset" ? "#dbeafe" : "#fff",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          Build from preset
        </button>
        <button
          type="button"
          onClick={() => setMode("upload")}
          style={{
            padding: "10px 14px",
            borderRadius: 999,
            border: mode === "upload" ? "1px solid #1d4ed8" : "1px solid #cbd5e1",
            background: mode === "upload" ? "#dbeafe" : "#fff",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          Upload actual stamp
        </button>
      </div>

      {mode === "preset" ? (
        <>
          {!canCustomize && (
            <div style={{ marginBottom: 16, padding: 14, borderRadius: 12, background: "#fffbeb", border: "1px solid #fde68a", color: "#92400e" }}>
              <div style={{ fontWeight: 700, marginBottom: 6 }}>Upload actual stamp is locked on the {currentPlan} plan.</div>
              <div style={{ marginBottom: 10 }}>Upgrade to Pro or Business to build branded stamps from the included layouts.</div>
              <button type="button" onClick={onUpgrade} style={upgradeButtonStyle}>
                Upgrade to Pro / Business
              </button>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 18 }}>
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                <div>
                  <label style={labelStyle}>Stamp name</label>
                  <input style={inputStyle} value={stampName} onChange={(e) => setStampName(e.target.value)} />
                </div>
                <div>
                  <label style={labelStyle}>Password</label>
                  <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Required to use stamp" />
                </div>
                <div>
                  <label style={labelStyle}>Shape</label>
                  <select style={inputStyle} value={shape} onChange={(e) => setShape(e.target.value)}>
                    <option value="circle">Circle</option>
                    <option value="rect">Rectangle</option>
                  </select>
                </div>
                <div>
                  <label style={labelStyle}>Preset style</label>
                  <select style={inputStyle} value={presetTemplate} onChange={(e) => setPresetTemplate(e.target.value)}>
                    <option value="classicSeal">Classic seal</option>
                    <option value="doubleRing">Double ring</option>
                    <option value="officeBox">Office box</option>
                    {shape === "circle" && <option value="corporateSeal">Traditional corporate seal</option>}
                    {shape === "circle" && <option value="modernCorporateSeal">Modern corporate seal</option>}
                  </select>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
                <div>
                  <label style={labelStyle}>Top text</label>
                  <input style={inputStyle} value={topText} onChange={(e) => setTopText(e.target.value)} />
                </div>
                <div>
                  <label style={labelStyle}>Center text</label>
                  <input style={inputStyle} value={centerText} onChange={(e) => setCenterText(e.target.value)} />
                </div>
                <div>
                  <label style={labelStyle}>Bottom text</label>
                  <input style={inputStyle} value={bottomText} onChange={(e) => setBottomText(e.target.value)} />
                </div>
              </div>

              {shape === "circle" && isCorporateStyle && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={labelStyle}>Inner arc wording</label>
                    <input style={inputStyle} value={corporateText} onChange={(e) => setCorporateText(e.target.value)} />
                  </div>
                  <div>
                    <label style={labelStyle}>Established year</label>
                    <input style={inputStyle} value={establishedYear} onChange={(e) => setEstablishedYear(e.target.value)} maxLength={12} />
                  </div>
                </div>
              )}

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
                <div>
                  <label style={labelStyle}>Border color</label>
                  <input style={inputStyle} type="color" value={borderColor} onChange={(e) => setBorderColor(e.target.value)} />
                </div>
                <div>
                  <label style={labelStyle}>Text color</label>
                  <input style={inputStyle} type="color" value={textColor} onChange={(e) => setTextColor(e.target.value)} />
                </div>
                <div>
                  <label style={labelStyle}>Border width</label>
                  <input style={inputStyle} type="number" min={1} max={12} value={borderWidth} onChange={(e) => setBorderWidth(Number(e.target.value) || 1)} />
                </div>
                <div>
                  <label style={labelStyle}>Font size</label>
                  <input style={inputStyle} type="number" min={14} max={52} value={fontSize} onChange={(e) => setFontSize(Number(e.target.value) || 20)} />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
                <div>
                  <label style={labelStyle}>Padding</label>
                  <input style={inputStyle} type="number" min={10} max={60} value={padding} onChange={(e) => setPadding(Number(e.target.value) || 18)} />
                </div>
                <div>
                </div>
                <div>
  <label style={labelStyle}>Logo X</label>
  <input
    style={inputStyle}
    type="number"
    value={logoX}
    onChange={(e) => setLogoX(Number(e.target.value) || 0)}
    disabled={!canUsePresetLogo}
  />
</div>

<div>
  <label style={labelStyle}>Logo Y</label>
  <input
    style={inputStyle}
    type="number"
    value={logoY}
    onChange={(e) => setLogoY(Number(e.target.value) || 0)}
    disabled={!canUsePresetLogo}
  />
</div>

<div>
  <label style={labelStyle}>Logo Width</label>
  <input
    style={inputStyle}
    type="number"
    value={logoW}
    onChange={(e) => setLogoW(Number(e.target.value) || 1)}
    disabled={!canUsePresetLogo}
  />
</div>

<div>
  <label style={labelStyle}>Logo Height</label>
  <input
    style={inputStyle}
    type="number"
    value={logoH}
    onChange={(e) => setLogoH(Number(e.target.value) || 1)}
    disabled={!canUsePresetLogo}
  />
</div>
              </div>

              <div style={{ marginBottom: 14, padding: 14, borderRadius: 12, border: "1px solid #dbe4f0", background: "#f8fafc" }}>
                <div style={{ fontWeight: 700, marginBottom: 8 }}>Add your company logo on a provided stamp layout</div>
                <div style={{ fontSize: 14, color: "#475569", marginBottom: 10 }}>
                  Pro and Business can upload a logo and place it inside the preset stamp templates.
                </div>
                <input type="file" accept="image/png,image/jpeg,image/webp" onChange={(e) => setLogoFile(e.target.files?.[0] || null)} disabled={!canUsePresetLogo} />
                {!canUsePresetLogo && (
                  <div style={{ marginTop: 8, color: "#92400e", fontSize: 13 }}>Logo overlays unlock on Pro and Business.</div>
                )}
                {logoPreview && (
                  <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 10 }}>
                    <img src={logoPreview} alt="Logo preview" style={{ width: 72, height: 72, objectFit: "contain", border: "1px solid #cbd5e1", borderRadius: 10, background: "#fff" }} />
                    <button type="button" onClick={() => setLogoFile(null)} style={ghostButton}>Remove logo</button>
                  </div>
                )}
              </div>

              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button type="button" onClick={useCircularPreset} style={ghostButton}>Use circular preset</button>
                <button type="button" onClick={useRectPreset} style={ghostButton}>Use rectangle preset</button>
                <button type="button" onClick={useCorporatePreset} style={ghostButton}>Use traditional corporate seal</button>
                <button type="button" onClick={useModernCorporatePreset} style={ghostButton}>Use modern corporate seal</button>
                <button type="button" onClick={exportPng} style={ghostButton}>Download preview PNG</button>
                <button type="button" onClick={savePresetStamp} disabled={busy || !canCustomize} style={primaryButton}>
                  {busy ? "Saving..." : hasLogoOverlay ? "Save branded preset stamp" : "Save preset stamp"}
                </button>
              </div>
            </div>

            <div>
              <div style={{ fontWeight: 700, marginBottom: 8 }}>Live preview</div>
              <div style={{ border: "1px solid #dbe4f0", borderRadius: 14, padding: 12, background: "linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%)" }}>
                <canvas ref={canvasRef} width={canvasWidth} height={canvasHeight} style={{ width: "100%", maxWidth: 420, display: "block", margin: "0 auto" }} />
              </div>
            </div>
          </div>
        </>
      ) : (
        <>
          {!canUploadActual && (
            <div style={{ marginBottom: 16, padding: 14, borderRadius: 12, background: "#fffbeb", border: "1px solid #fde68a", color: "#92400e" }}>
              <div style={{ fontWeight: 700, marginBottom: 6 }}>Actual stamp upload is locked on the {currentPlan} plan.</div>
              <div style={{ marginBottom: 10 }}>Upgrade to Pro or Business to upload your scanned signature stamp or transparent PNG stamp for direct use.</div>
              <button type="button" onClick={() => onUpgrade?.()} style={{ padding: "10px 14px", borderRadius: 10, border: 0, background: "#f59e0b", color: "#111827", fontWeight: 700, cursor: "pointer" }}>
                Upgrade to Pro
              </button>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
           <div>
  <label style={labelStyle}>Stamp name</label>

  <input
    value={stampName}
    onChange={(e) => setStampName(e.target.value)}
    placeholder="Company seal"
    style={{
      ...inputStyle,
      background: canUploadActual ? "#ffffff" : "#f1f5f9",
      color: canUploadActual ? "#0f172a" : "#94a3b8",
      cursor: canUploadActual ? "text" : "not-allowed",
    }}
    disabled={!canUploadActual}
  />
</div>

<div>
  <label style={labelStyle}>Password</label>

  <input
    type="password"
    value={password}
    onChange={(e) => setPassword(e.target.value)}
    placeholder="Required to use stamp"
    style={{
      ...inputStyle,
      background: canUploadActual ? "#ffffff" : "#f1f5f9",
      color: canUploadActual ? "#0f172a" : "#94a3b8",
      cursor: canUploadActual ? "text" : "not-allowed",
    }}
    disabled={!canUploadActual}
  />
</div>
            
          </div>

          <div style={{ marginTop: 14, padding: 16, borderRadius: 12, border: "1px solid #dbe4f0", background: "#f8fafc" }}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Upload your actual stamp</div>
            <div style={{ marginBottom: 10, color: "#475569", fontSize: 14 }}>Use a transparent PNG for the cleanest result. JPG and WEBP previews are fine, but PNG is recommended for real stamping.</div>
            <input type="file" accept="image/png,image/jpeg,image/webp" onChange={(e) => setUploadFile(e.target.files?.[0] || null)} disabled={!canUploadActual} />
            {uploadPreview && (
              <div style={{ marginTop: 12, display: "flex", gap: 16, alignItems: "center" }}>
                <img src={uploadPreview} alt="Uploaded stamp preview" style={{ maxWidth: 220, maxHeight: 160, objectFit: "contain", border: "1px solid #cbd5e1", borderRadius: 12, background: "#fff", padding: 10 }} />
                <button type="button" onClick={() => setUploadFile(null)} style={ghostButton}>Remove file</button>
              </div>
            )}
          </div>

          <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button type="button" onClick={saveUploadedStamp} disabled={busy || !canUploadActual} style={primaryButton}>
              {busy ? "Uploading..." : "Upload actual stamp"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

const labelStyle = {
  display: "block",
  fontSize: 13,
  fontWeight: 700,
  marginBottom: 6,
  color: "#334155",
};

const inputStyle = {
  width: "100%",
  border: "1px solid #cbd5e1",
  borderRadius: 10,
  padding: "10px 12px",
  background: "#fff",
  boxSizing: "border-box",
};

const primaryButton = {
  padding: "10px 14px",
  borderRadius: 10,
  border: 0,
  background: "#1d4ed8",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
};

const ghostButton = {
  padding: "10px 14px",
  borderRadius: 10,
  border: "1px solid #cbd5e1",
  background: "#fff",
  color: "#0f172a",
  fontWeight: 700,
  cursor: "pointer",
};
