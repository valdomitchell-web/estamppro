import React, { useEffect, useRef, useState } from "react";
import { api } from "./api";

export default function StampDesigner({ onSaved }) {
  const canvasEl = useRef(null);
  const fileInputRef = useRef(null);
  const fabricRef = useRef(null);

  const [canvas, setCanvas] = useState(null);
  const [name, setName] = useState("My Designed Stamp");
  const [ready, setReady] = useState(false);
  const [imageLoading, setImageLoading] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState("");

  useEffect(() => {
    let disposed = false;
    let localCanvas = null;

    (async () => {
      try {
        const mod = await import("fabric");
        const fabric = mod.fabric || mod.default || mod;
        fabricRef.current = fabric;

        localCanvas = new fabric.Canvas(canvasEl.current, {
          width: 400,
          height: 300,
          backgroundColor: "rgba(255,255,255,0)",
          preserveObjectStacking: true,
        });

        if (!disposed) {
          setCanvas(localCanvas);
          setReady(true);
        }
      } catch (e) {
        console.error("Failed to load fabric:", e);
        alert("Failed to load designer. Try installing fabric and refresh.");
      }
    })();

    return () => {
      disposed = true;
      try {
        if (localCanvas) localCanvas.dispose();
      } catch {}
    };
  }, []);

  const ensure = () => {
    const fabric = fabricRef.current;
    if (!fabric || !canvas) {
      alert("Designer not ready yet.");
      return null;
    }
    return fabric;
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

  const openFilePicker = () => {
    fileInputRef.current?.click();
  };

  const addText = () => {
    const fabric = ensure();
    if (!fabric) return;

    const t = new fabric.IText("Edit me", {
      left: 50,
      top: 50,
      fontSize: 24,
      fill: "#111827",
      fontFamily: "Arial",
    });

    canvas.add(t);
    canvas.setActiveObject(t);
    canvas.renderAll();
  };

  const addCircle = () => {
    const fabric = ensure();
    if (!fabric) return;

    const circle = new fabric.Circle({
      left: 100,
      top: 90,
      radius: 80,
      stroke: "#2563eb",
      strokeWidth: 4,
      fill: "rgba(0,0,0,0)",
    });

    canvas.add(circle);
    canvas.setActiveObject(circle);
    canvas.renderAll();
  };

  const addRect = () => {
    const fabric = ensure();
    if (!fabric) return;

    const rect = new fabric.Rect({
      left: 60,
      top: 60,
      width: 260,
      height: 180,
      stroke: "#ef4444",
      strokeWidth: 3,
      fill: "rgba(0,0,0,0)",
    });

    canvas.add(rect);
    canvas.setActiveObject(rect);
    canvas.renderAll();
  };

  const removeSelected = () => {
    const fabric = ensure();
    if (!fabric) return;

    const active = canvas.getActiveObject();
    if (!active) {
      alert("Select an item first.");
      return;
    }

    canvas.remove(active);
    canvas.discardActiveObject();
    canvas.renderAll();
  };

  const addLogo = (e) => {
    const fabric = ensure();
    if (!fabric) return;

    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFileName(file.name);
    setImageLoading(true);

    const failSafe = setTimeout(() => {
      setImageLoading(false);
    }, 8000);

    const reader = new FileReader();

    reader.onload = async () => {
      try {
        const dataUrl = reader.result;
        if (!dataUrl) throw new Error("No image data returned");

        const fromURL = fabric.Image?.fromURL || fabric.FabricImage?.fromURL;
        if (!fromURL) {
          throw new Error("Fabric image loader not available");
        }

        let img;

        if (fromURL.length >= 2) {
          img = await new Promise((resolve, reject) => {
            try {
              fromURL.call(
                fabric.Image || fabric.FabricImage,
                dataUrl,
                (loadedImg) => {
                  if (!loadedImg) {
                    return reject(new Error("Failed to load image"));
                  }
                  resolve(loadedImg);
                },
                { crossOrigin: null }
              );
            } catch (err) {
              reject(err);
            }
          });
        } else {
          img = await fromURL.call(
            fabric.Image || fabric.FabricImage,
            dataUrl,
            { crossOrigin: null }
          );
        }

        if (!img) throw new Error("Image could not be created");

        const maxW = canvas.getWidth() * 0.6;
        const maxH = canvas.getHeight() * 0.6;

        const imgW = img.width || 1;
        const imgH = img.height || 1;

        const scaleX = maxW / imgW;
        const scaleY = maxH / imgH;
        const scale = Math.min(scaleX, scaleY, 1);

        img.set({
          left: 50,
          top: 50,
          scaleX: scale,
          scaleY: scale,
          selectable: true,
          hasControls: true,
          hasBorders: true,
        });

        canvas.add(img);
        canvas.setActiveObject(img);
        canvas.renderAll();
      } catch (err) {
        console.error("Image load failed:", err);
        alert("Failed to load image into the designer.");
      } finally {
        clearTimeout(failSafe);
        setImageLoading(false);
      }
    };

    reader.onerror = () => {
      clearTimeout(failSafe);
      setImageLoading(false);
      alert("Could not read image file.");
    };

    reader.readAsDataURL(file);
    e.target.value = "";
  };

  const exportPNG = async () => {
    const fabric = ensure();
    if (!fabric) return;

    canvas.discardActiveObject();
    canvas.renderAll();

    const dataUrl = canvas.toDataURL({
      format: "png",
      multiplier: 2,
      enableRetinaScaling: true,
    });

    const { saveAs } = await import("file-saver");
    saveAs(dataUrl, `${name || "stamp"}.png`);
  };

  const saveAsStamp = async () => {
    const fabric = ensure();
    if (!fabric) return;

    if (imageLoading) {
      alert("Please wait for the image to finish loading.");
      return;
    }

    canvas.discardActiveObject();
    canvas.renderAll();

    const multiplier = 2;
    const dataUrl = canvas.toDataURL({
      format: "png",
      multiplier,
      enableRetinaScaling: true,
    });

    const res = await fetch(dataUrl);
    const blob = await res.blob();

    if (!blob || blob.size < 500) {
      alert("The stamp looks empty. Add text, shapes, or an image first.");
      return;
    }

    const password = prompt("Set a stamp password (used when applying this stamp)");
    if (!password) {
      alert("Password required");
      return;
    }

    const w = Math.round(canvas.getWidth() * multiplier);
    const h = Math.round(canvas.getHeight() * multiplier);

    const form = new FormData();
    form.append("image", new File([blob], `${name || "stamp"}.png`, { type: "image/png" }));
    form.append("name", name || "Untitled Stamp");
    form.append("password", password);
    form.append("width", String(w));
    form.append("height", String(h));

    const r = await api.post("/stamps", form, {
      headers: { "Content-Type": "multipart/form-data" },
      withCredentials: true,
    });

    alert("Stamp saved!");

    if (typeof onSaved === "function") {
      onSaved(r.data?.stamp);
    }
  };

  useEffect(() => {
    const onKeyDown = (e) => {
      if (e.key !== "Delete" && e.key !== "Backspace") return;
      if (!canvas) return;

      const active = canvas.getActiveObject();
      if (!active) return;

      canvas.remove(active);
      canvas.discardActiveObject();
      canvas.renderAll();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [canvas]);

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
      //<h2 style={{ marginTop: 0, color: "#0f172a" }}>Stamp Designer</h2>

      <div
        style={{
          display: "flex",
          gap: 8,
          flexWrap: "wrap",
          alignItems: "center",
          marginBottom: 12,
        }}
      >
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Stamp name"
          style={{
            padding: "10px 12px",
            borderRadius: 10,
            border: "1px solid #cbd5e1",
            minWidth: 220,
          }}
        />

        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={addLogo}
          style={{ display: "none" }}
        />

        <button type="button" onClick={openFilePicker} style={toolButtonStyle}>
          Choose Image
        </button>

        <span style={{ color: "#555" }}>
          {selectedFileName || "No file chosen"}
        </span>

        <button onClick={addText} disabled={!ready} style={toolButtonStyle}>
          Add Text
        </button>

        <button onClick={addCircle} disabled={!ready} style={toolButtonStyle}>
          Add Circle
        </button>

        <button onClick={addRect} disabled={!ready} style={toolButtonStyle}>
          Add Rectangle
        </button>

        <button onClick={removeSelected} disabled={!ready} style={toolButtonStyle}>
          Remove Selected
        </button>
      </div>

      <canvas
        ref={canvasEl}
        style={{
          border: "1px dashed #94a3b8",
          background: "transparent",
          maxWidth: "100%",
          borderRadius: 8,
        }}
      />

      <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button onClick={exportPNG} disabled={!ready || imageLoading} style={toolButtonStyle}>
          Download PNG
        </button>

        <button
          onClick={saveAsStamp}
          disabled={!ready || imageLoading}
          style={primaryButtonStyle}
        >
          Save as Stamp
        </button>
      </div>

      {imageLoading && (
        <div style={{ marginTop: 8, color: "#555" }}>
          Loading image...
        </div>
      )}

      <small style={{ display: "block", marginTop: 10, color: "#6b7280" }}>
        Tip: click elements to move/resize; double-click text to edit; press Delete to remove selected items.
      </small>
    </div>
  );
}