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

  const [borderColor, setBorderColor] = useState(branding?.primary_color || "#b91c1c");
  const [textColor, setTextColor] = useState(branding?.accent_color || branding?.primary_color || "#991b1b");
  const [borderWidth, setBorderWidth] = useState(6);
  const [fontSize, setFontSize] = useState(28);
  const [padding, setPadding] = useState(24);
  const [showQrBox, setShowQrBox] = useState(true);

  const [uploadFile, setUploadFile] = useState(null);
  const [uploadPreview, setUploadPreview] = useState("");

  const [logoFile, setLogoFile] = useState(null);
  const [logoPreview, setLogoPreview] = useState("");
  const [logoPlacement, setLogoPlacement] = useState("center");
  const [busy, setBusy] = useState(false);

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
      return;
    }
    const url = URL.createObjectURL(logoFile);
    setLogoPreview(url);
    const img = new Image();
    img.onload = () => {
      logoImgRef.current = img;
      drawStamp();
    };
    img.src = url;
    return () => URL.revokeObjectURL(url);
  }, [logoFile]);

  const hasLogoOverlay = useMemo(() => canUsePresetLogo && !!logoPreview, [canUsePresetLogo, logoPreview]);

  useEffect(() => {
    drawStamp();
  }, [
    mode,
    shape,
    presetTemplate,
    topText,
    centerText,
    bottomText,
    borderColor,
    textColor,
    borderWidth,
    fontSize,
    padding,
    showQrBox,
    logoPlacement,
    logoPreview,
  ]);

  const drawLogoOverlay = (ctx, canvas, logoImg) => {
  if (!logoImg || !canUsePresetLogo) return;

  const cx = canvas.width / 2;
  const cy = canvas.height / 2;

  let logoW = 90;
  let logoH = 90;

  const aspect = logoImg.width / Math.max(logoImg.height, 1);

  if (aspect >= 1) {
    logoH = logoW / aspect;
  } else {
    logoW = logoH * aspect;
  }

  let x = cx - logoW / 2;
  let y = cy - logoH / 2;

  if (logoPlacement === "top") {
    x = cx - logoW / 2;
    y = 110;
  }

  if (logoPlacement === "left") {
    x = 110;
    y = cy - logoH / 2;
  }

  ctx.save();
  ctx.globalAlpha = 0.95;
  ctx.drawImage(logoImg, x, y, logoW, logoH);
  ctx.restore();
};

  function drawArcText(ctx, text, cx, cy, radius, startAngle, arcAngle, size, color, reverse = false) {
    const value = String(text || "").trim();
    if (!value) return;
    const chars = value.split("");
    ctx.save();
    ctx.fillStyle = color;
    ctx.font = `bold ${size}px Arial`;
    const spacing = chars.length > 1 ? arcAngle / (chars.length - 1) : 0;
    chars.forEach((char, idx) => {
      const angle = reverse ? startAngle + arcAngle - spacing * idx : startAngle + spacing * idx;
      ctx.save();
      ctx.translate(cx + Math.cos(angle) * radius, cy + Math.sin(angle) * radius);
      ctx.rotate(angle + (reverse ? Math.PI / 2 : Math.PI / 2));
      ctx.fillText(char, 0, 0);
      ctx.restore();
    });
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
        ctx.beginPath();
        ctx.arc(cx, cy, radius - 34, 0, Math.PI * 2);
        ctx.stroke();
      }

      drawArcText(ctx, topText, cx, cy, radius - 28, -Math.PI * 0.78, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor);
      drawArcText(ctx, bottomText, cx, cy, radius - 28, Math.PI * 0.22, Math.PI * 0.56, Math.max(18, fontSize * 0.7), textColor, true);

      if (hasLogoOverlay && logoImg && logoPlacement === "center") {
  drawLogoOverlay(ctx, canvas, logoImg);
  ctx.font = `bold ${Math.max(18, fontSize * 0.72)}px Arial`;
  ctx.fillText(centerText, cx, cy + 68);
} else {
        ctx.font = `bold ${fontSize}px Arial`;
        ctx.fillText(centerText, cx, cy);
      }

      if (hasLogoOverlay && logoImg && logoPlacement === "top") {
  drawLogoOverlay(ctx, canvas, logoImg);
}

      if (showQrBox) {
        ctx.strokeStyle = borderColor;
        ctx.lineWidth = 2;
        const qrSize = 55;
        ctx.strokeRect(cx - qrSize / 2, cy + 82, qrSize, qrSize);
        ctx.font = `10px Arial`;
        ctx.fillText("QR", cx, cy + 106);
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

      if (showQrBox) {
        ctx.lineWidth = 2;
        const qrSize = 55;
        ctx.strokeRect(rectX + rectW - qrSize - 24, rectY + 24, qrSize, qrSize);
        ctx.font = `12px Arial`;
        ctx.fillText("QR", rectX + rectW - qrSize / 2 - 24, rectY + 24 + qrSize / 2);
      }
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
      form.append("borderColor", borderColor);
      form.append("textColor", textColor);
      form.append("borderWidth", String(borderWidth));
      form.append("fontSize", String(fontSize));
      form.append("padding", String(padding));
      form.append("showQrBox", String(showQrBox));
      form.append("presetTemplate", presetTemplate);
      form.append("logoIncluded", String(hasLogoOverlay));
      form.append("logoPlacement", logoPlacement);

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
    setShowQrBox(true);
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
    setShowQrBox(true);
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
                  <label style={labelStyle}>QR box</label>
                  <select style={inputStyle} value={String(showQrBox)} onChange={(e) => setShowQrBox(e.target.value === "true")}>
                    <option value="true">Show</option>
                    <option value="false">Hide</option>
                  </select>
                </div>
                <div>
                  <label style={labelStyle}>Preset logo placement</label>
                  <select style={inputStyle} value={logoPlacement} onChange={(e) => setLogoPlacement(e.target.value)} disabled={!canUsePresetLogo}>
                    <option value="center">Center</option>
                    <option value="top">Top</option>
                    <option value="left">Left block</option>
                  </select>
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
              <input style={inputStyle} value={stampName} onChange={(e) => setStampName(e.target.value)} placeholder="Company seal" />
            </div>
            <div>
              <label style={labelStyle}>Password</label>
              <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Required to use stamp" />
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
